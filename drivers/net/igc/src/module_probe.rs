//! Loadable-module registration + datapath path for igc.
//!
//! Implements a copy datapath through the device C ABI. Physical acceptance
//! is tracked in the network specification. When a matching device is probed, the
//! kernel installs a per-device context (cap + BAR/DMA handles) and calls
//! [`probe_c`], which — using only KSYMTAB exports — enables the device, maps
//! BAR0, resets the controller, installs copy-mode DMA rings, registers an
//! Ethernet interface, and drives RX/TX from task-context IRQ/poller callbacks
//! in the operator-selected isolation domain.
//!
//! A module build links ONLY these KSYMTAB imports — no kernel crates — so the
//! `.ko`'s undefined-symbol set stays within the exported ABI (xtask's `nm -u`
//! gate enforces it).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Intel.
const IGC_VENDOR: u16 = 0x8086;

// C ABI datapath adapter. Shared hardware.rs owns the controller protocol.
const IGC_CTRL: u64 = 0x0000;
const IGC_STATUS: u64 = 0x0008;
const IGC_ICR: u64 = 0x1500;
const IGC_IMS: u64 = 0x1508;
const IGC_RDT: u64 = 0xC018;
const IGC_TDT: u64 = 0xE018;
const IGC_RAL0: u64 = 0x5400;
const IGC_RAH0: u64 = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const RXD_STAT_DD: u8 = 1 << 0;
const RXD_STAT_EOP: u8 = 1 << 1;
const TXD_STAT_DD: u8 = 1 << 0;
const IMS_DEFAULT: u32 = (1 << 7) | (1 << 6) | (1 << 4) | (1 << 2) | (1 << 0);

const TX_RING_LEN: usize = 64;
const RX_RING_LEN: usize = 256;
const DMA_BUF_LEN: usize = 2048;
const DESC_LEN: usize = 16;

// Module builds have no allocator: retain up to 32 independent device states.
// Slots are never recycled while module text is live, including failed probes,
// so an old callback cannot resolve to a replacement device's DMA buffers.
const MAX_DEVICES: usize = 32;

struct DeviceState {
    dev_token: AtomicU64,
    bar0: AtomicU64,
    tx_ring: AtomicU64,
    rx_ring: AtomicU64,
    ifindex: AtomicU32,
    tx_tail: AtomicU32,
    rx_head: AtomicU32,
    tx_busy: AtomicBool,
    ready: AtomicBool,
    tx_bufs: [AtomicU64; TX_RING_LEN],
    tx_addrs: [AtomicU64; TX_RING_LEN],
    rx_bufs: [AtomicU64; RX_RING_LEN],
    rx_addrs: [AtomicU64; RX_RING_LEN],
}

impl DeviceState {
    const fn new() -> Self {
        Self {
            dev_token: AtomicU64::new(0),
            bar0: AtomicU64::new(0),
            tx_ring: AtomicU64::new(0),
            rx_ring: AtomicU64::new(0),
            ifindex: AtomicU32::new(0),
            tx_tail: AtomicU32::new(0),
            rx_head: AtomicU32::new(0),
            tx_busy: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            tx_bufs: [const { AtomicU64::new(0) }; TX_RING_LEN],
            tx_addrs: [const { AtomicU64::new(0) }; TX_RING_LEN],
            rx_bufs: [const { AtomicU64::new(0) }; RX_RING_LEN],
            rx_addrs: [const { AtomicU64::new(0) }; RX_RING_LEN],
        }
    }
}

static DEVICES: [DeviceState; MAX_DEVICES] = [const { DeviceState::new() }; MAX_DEVICES];

fn device_state(token: u64) -> Option<&'static DeviceState> {
    if token == 0 {
        return None;
    }
    DEVICES
        .iter()
        .find(|state| state.dev_token.load(Ordering::Acquire) == token)
}

fn reserve_device(token: u64) -> Result<&'static DeviceState, i32> {
    if token == 0 {
        return Err(-22);
    }
    for state in &DEVICES {
        match state
            .dev_token
            .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => return Ok(state),
            Err(existing) if existing == token => return Err(-16),
            Err(_) => {}
        }
    }
    Err(-28) // ENOSPC, without disturbing any bound device.
}

// PCI command-register bits.
const PCI_CMD_MEM_SPACE: u16 = 1 << 1;
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

unsafe extern "C" {
    fn narf_monotonic_ns() -> u64;
    fn narf_dma_retain_on_teardown(dev: u64, retain: u32) -> i32;
    /// KSYMTAB export (`modules/src/kabi.rs`). `probe` is a `ModuleProbeFn`
    /// address: `extern "C" fn(dev_token: u64, reserved: u64) -> i32`.
    fn narf_register_pci_driver(
        name: *const u8,
        name_len: usize,
        vendor: u16,
        device: u16,
        probe: usize,
    ) -> i32;
    fn narf_printk(ptr: *const u8, len: usize) -> i32;
    fn narf_pci_prepare_probe(dev: u64) -> i32;
    fn narf_pci_enable(dev: u64, cmd_bits: u16) -> i32;
    fn narf_bar_map(dev: u64, bar_idx: u8) -> u64;
    fn narf_mmio_read32(dev: u64, bar: u64, off: u64, out: *mut u32) -> i32;
    fn narf_mmio_write32(dev: u64, bar: u64, off: u64, value: u32) -> i32;
    fn narf_mmio_wait32(
        dev: u64,
        bar: u64,
        off: u64,
        mask: u32,
        expected: u32,
        timeout_ns: u64,
    ) -> i32;
    fn narf_dma_alloc(dev: u64, len: usize) -> u64;
    fn narf_dma_addr(dev: u64, dma: u64, off: u64, out: *mut u64) -> i32;
    fn narf_dma_write(dev: u64, dma: u64, off: u64, src: *const u8, len: usize) -> i32;
    fn narf_dma_read(dev: u64, dma: u64, off: u64, dst: *mut u8, len: usize) -> i32;
    fn narf_dma_wait8(dev: u64, dma: u64, off: u64, mask: u8, expected: u8, timeout_ns: u64)
        -> i32;
    fn narf_dma_free(dev: u64, dma: u64) -> i32;
    fn narf_msix_enable(dev: u64) -> i32;
    fn narf_msix_claim(dev: u64, out_vector: *mut u16) -> i32;
    fn narf_irq_set_handler(dev: u64, vector: u16, callback: usize, cookie: u64) -> i32;
    fn narf_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
    fn narf_netif_register_with_context(
        dev: u64,
        mac: *const u8,
        tx_callback: usize,
        out_ifindex: *mut u32,
    ) -> i32;
    fn narf_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32;
}

fn log(msg: &str) {
    // SAFETY: `msg` is a live `&str` for the call's duration.
    unsafe {
        let _ = narf_printk(msg.as_ptr(), msg.len());
    }
}

fn mmio_read(dev: u64, bar: u64, off: u64) -> Result<u32, i32> {
    let mut value = 0u32;
    // SAFETY: callers use register offsets from the igc BAR0 map; the kernel
    // validates the opaque context and BAR bounds.
    let rc = unsafe { narf_mmio_read32(dev, bar, off, &mut value) };
    if rc == 0 {
        Ok(value)
    } else {
        Err(rc)
    }
}

fn mmio_write(dev: u64, bar: u64, off: u64, value: u32) -> Result<(), i32> {
    // SAFETY: same BAR ownership/bounds contract as `mmio_read`.
    let rc = unsafe { narf_mmio_write32(dev, bar, off, value) };
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

fn dma_address(dev: u64, handle: u64) -> Result<u64, i32> {
    let mut address = 0u64;
    // SAFETY: `handle` was allocated for `dev`; output is a writable local.
    let rc = unsafe { narf_dma_addr(dev, handle, 0, &mut address) };
    if rc == 0 && address != 0 {
        Ok(address)
    } else {
        Err(if rc == 0 { -5 } else { rc })
    }
}

fn rx_descriptor(address: u64) -> [u8; DESC_LEN] {
    let mut desc = [0u8; DESC_LEN];
    desc[..8].copy_from_slice(&address.to_le_bytes());
    desc
}

fn tx_descriptor(address: u64, len: usize) -> [u8; DESC_LEN] {
    let mut desc = [0u8; DESC_LEN];
    desc[..8].copy_from_slice(&address.to_le_bytes());
    desc[8..12].copy_from_slice(&(0x2b300000 | len as u32).to_le_bytes());
    desc[12..].copy_from_slice(&((len as u32) << 14).to_le_bytes());
    desc
}

fn init_dma_rings(state: &DeviceState, dev: u64, bar: u64) -> Result<(), i32> {
    // igc requires TDLEN/RDLEN to be 128-byte multiples. A page-sized
    // allocation keeps both rings naturally aligned and leaves growth room.
    // SAFETY: allocations are retained by the device context until teardown.
    let tx_ring = unsafe { narf_dma_alloc(dev, 4096) };
    // SAFETY: same.
    let rx_ring = unsafe { narf_dma_alloc(dev, 4096) };
    if tx_ring == 0 || rx_ring == 0 {
        return Err(-12);
    }
    let tx_ring_addr = dma_address(dev, tx_ring)?;
    let rx_ring_addr = dma_address(dev, rx_ring)?;

    for slot in 0..TX_RING_LEN {
        // SAFETY: one persistent buffer per descriptor slot.
        let buffer = unsafe { narf_dma_alloc(dev, DMA_BUF_LEN) };
        if buffer == 0 {
            return Err(-12);
        }
        let address = dma_address(dev, buffer)?;
        state.tx_bufs[slot].store(buffer, Ordering::Relaxed);
        state.tx_addrs[slot].store(address, Ordering::Relaxed);
    }

    for slot in 0..RX_RING_LEN {
        // SAFETY: one persistent receive buffer per descriptor slot.
        let buffer = unsafe { narf_dma_alloc(dev, DMA_BUF_LEN) };
        if buffer == 0 {
            return Err(-12);
        }
        let address = dma_address(dev, buffer)?;
        let desc = rx_descriptor(address);
        // SAFETY: the descriptor range lies inside the 4-KiB ring allocation.
        if unsafe {
            narf_dma_write(
                dev,
                rx_ring,
                (slot * DESC_LEN) as u64,
                desc.as_ptr(),
                desc.len(),
            )
        } != 0
        {
            return Err(-5);
        }
        state.rx_bufs[slot].store(buffer, Ordering::Relaxed);
        state.rx_addrs[slot].store(address, Ordering::Relaxed);
    }

    // SAFETY: allocations belong to this context; retention precedes DMA.
    if unsafe { narf_dma_retain_on_teardown(dev, 1) } != 0 {
        return Err(-5);
    }
    let regs = ModuleRegisters { dev, bar };
    let mac = super::hardware::read_mac(&regs).map_err(|_| -5)?;
    super::hardware::configure_tables(&regs, mac, 1500, &[0x6d; 40], &[0; 128]);
    super::hardware::queue_sized(
        &regs,
        0,
        tx_ring_addr,
        rx_ring_addr,
        TX_RING_LEN,
        RX_RING_LEN,
    )
    .map_err(|_| -5)?;
    super::hardware::activate_queues(&regs, &[RX_RING_LEN], || {
        // SAFETY: all programmed rings and buffers belong to this retained
        // context. The ABI verifies the Command readback before activation.
        if unsafe { narf_pci_enable(dev, PCI_CMD_BUS_MASTER) } != 0 {
            return Err(super::protocol::IgcError::Other("PCI DMA enable rejected"));
        }
        Ok(())
    })
    .map_err(|_| -5)?;
    state.tx_ring.store(tx_ring, Ordering::Relaxed);
    state.rx_ring.store(rx_ring, Ordering::Relaxed);
    state.tx_tail.store(0, Ordering::Relaxed);
    state.rx_head.store(0, Ordering::Relaxed);
    Ok(())
}

fn transmit_frame(state: &DeviceState, frame: &[u8]) -> i32 {
    if frame.is_empty() || frame.len() > 1518 || !state.ready.load(Ordering::Acquire) {
        return -90; // -EMSGSIZE / not ready
    }
    if state
        .tx_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return -11; // -EAGAIN
    }
    let rc = transmit_frame_locked(state, frame);
    state.tx_busy.store(false, Ordering::Release);
    rc
}

fn transmit_frame_locked(state: &DeviceState, frame: &[u8]) -> i32 {
    let dev = state.dev_token.load(Ordering::Acquire);
    let bar = state.bar0.load(Ordering::Acquire);
    let ring = state.tx_ring.load(Ordering::Acquire);
    let tail = state.tx_tail.load(Ordering::Relaxed) as usize % TX_RING_LEN;
    let buffer = state.tx_bufs[tail].load(Ordering::Relaxed);
    let address = state.tx_addrs[tail].load(Ordering::Relaxed);
    if dev == 0 || bar == 0 || ring == 0 || buffer == 0 || address == 0 {
        return -19;
    }
    // SAFETY: frame is borrowed for this callback; the DMA destination is the
    // persistent buffer assigned to `tail`.
    if unsafe { narf_dma_write(dev, buffer, 0, frame.as_ptr(), frame.len()) } != 0 {
        return -5;
    }
    let desc = tx_descriptor(address, frame.len());
    let desc_off = (tail * DESC_LEN) as u64;
    // SAFETY: `tail` is bounded by the ring length.
    if unsafe { narf_dma_write(dev, ring, desc_off, desc.as_ptr(), desc.len()) } != 0 {
        return -5;
    }
    let next = ((tail + 1) % TX_RING_LEN) as u32;
    if mmio_write(dev, bar, IGC_TDT, next).is_err() {
        return -5;
    }
    // SAFETY: byte 12 is the device-owned legacy TX descriptor status. The
    // kernel bridge supplies the responsive, deadline-bounded wait loop.
    let waited = unsafe {
        narf_dma_wait8(
            dev,
            ring,
            desc_off + 12,
            TXD_STAT_DD,
            TXD_STAT_DD,
            250_000_000,
        )
    };
    if waited != 0 {
        state.ready.store(false, Ordering::Release);
        return waited;
    }
    state.tx_tail.store(next, Ordering::Release);
    0
}

extern "C" fn net_tx(dev_token: u64, frame: *const u8, len: usize) -> i32 {
    if frame.is_null() {
        return -22;
    }
    let Some(state) = device_state(dev_token) else {
        return -19;
    };
    // SAFETY: the kernel net bridge borrows exactly `len` readable bytes for
    // this synchronous callback and retains ownership.
    transmit_frame(state, unsafe { core::slice::from_raw_parts(frame, len) })
}

fn poll_receive(state: &DeviceState, dev: u64, bar: u64) -> i32 {
    let ring = state.rx_ring.load(Ordering::Acquire);
    let ifindex = state.ifindex.load(Ordering::Acquire);
    if ring == 0 || ifindex == 0 {
        return -19;
    }
    // DMA initializes exactly the prefix handed to the network stack. Avoid
    // clearing all 2 KiB here: compiler lowering would otherwise require a
    // `memset` relocation from module text.
    let mut frame = core::mem::MaybeUninit::<[u8; DMA_BUF_LEN]>::uninit();
    let frame_ptr = frame.as_mut_ptr().cast::<u8>();
    for _ in 0..RX_RING_LEN {
        let head = state.rx_head.load(Ordering::Relaxed) as usize % RX_RING_LEN;
        // DD first, as one byte load. The 16-byte copy below is a `memcpy`
        // whose load order is unspecified; taken while the device may still
        // be completing the slot it can pair a fresh DD with the armed
        // slot's length. Copy the descriptor only once DD says it is whole
        // (Linux: DD test, `dma_rmb()`, then the rest).
        let mut status = 0u8;
        // SAFETY: byte 8 of the descriptor slot is inside the retained
        // ring; `status` is one writable byte.
        if unsafe { narf_dma_read(dev, ring, (head * DESC_LEN + 8) as u64, &mut status, 1) } != 0 {
            return -5;
        }
        if status & RXD_STAT_DD == 0 {
            break;
        }
        let mut desc = [0u8; DESC_LEN];
        // SAFETY: descriptor slot is inside the retained ring.
        if unsafe {
            narf_dma_read(
                dev,
                ring,
                (head * DESC_LEN) as u64,
                desc.as_mut_ptr(),
                desc.len(),
            )
        } != 0
        {
            return -5;
        }
        if desc[8] & RXD_STAT_DD == 0 {
            break;
        }
        let len = u16::from_le_bytes([desc[12], desc[13]]) as usize;
        let complete = desc[8] & RXD_STAT_EOP != 0 && desc[11] & 0x80 == 0;
        let buffer = state.rx_bufs[head].load(Ordering::Relaxed);
        if complete && (14..=DMA_BUF_LEN).contains(&len) {
            // SAFETY: `len` is bounded by the persistent RX buffer size.
            if unsafe { narf_dma_read(dev, buffer, 0, frame_ptr, len) } != 0 {
                return -5;
            }
            // SAFETY: `frame[..len]` is writable for this synchronous stack
            // delivery and the registered ifindex belongs to `dev`.
            if unsafe { narf_netif_rx(dev, ifindex, frame_ptr, len) } != 0 {
                return -5;
            }
        }

        let address = state.rx_addrs[head].load(Ordering::Relaxed);
        let fresh = rx_descriptor(address);
        // SAFETY: re-arm the descriptor only after the frame was consumed.
        if unsafe {
            narf_dma_write(
                dev,
                ring,
                (head * DESC_LEN) as u64,
                fresh.as_ptr(),
                fresh.len(),
            )
        } != 0
        {
            return -5;
        }
        if mmio_write(dev, bar, IGC_RDT, head as u32).is_err() {
            return -5;
        }
        state
            .rx_head
            .store(((head + 1) % RX_RING_LEN) as u32, Ordering::Release);
    }
    0
}

extern "C" fn datapath_poll(dev_token: u64) -> i32 {
    let Some(state) = device_state(dev_token) else {
        return -19;
    };
    if !state.ready.load(Ordering::Acquire) || state.dev_token.load(Ordering::Acquire) != dev_token
    {
        return -19;
    }
    let bar = state.bar0.load(Ordering::Acquire);
    // ICR is read-to-clear. IRQ delivery and periodic fallback share this
    // callback, so acknowledging here is safe for both modes.
    let _ = mmio_read(dev_token, bar, IGC_ICR);
    poll_receive(state, dev_token, bar)
}

/// C-ABI probe thunk. Brings the I225/I226 up through opaque kernel handles and
/// registers the copy-mode interface. A bogus token fails closed.
extern "C" fn probe_c(dev_token: u64, _reserved: u64) -> i32 {
    probe_device(dev_token, false)
}
extern "C" fn probe_gigabit(dev_token: u64, _reserved: u64) -> i32 {
    probe_device(dev_token, true)
}
fn probe_device(dev_token: u64, gigabit: bool) -> i32 {
    let state = match reserve_device(dev_token) {
        Ok(state) => state,
        Err(errno) => return errno,
    };
    // SAFETY: C-ABI kernel export; `dev_token` is the call-gated handle this
    // probe was invoked with.
    if unsafe { narf_pci_prepare_probe(dev_token) } != 0 {
        return -5;
    }
    // SAFETY: C-ABI kernel export; BAR 0 belongs to `dev_token`.
    let bar0 = unsafe { narf_bar_map(dev_token, 0) };
    if bar0 == 0 {
        return -5;
    }
    // SAFETY: BAR sizing/mapping completed with decode and mastering parked.
    if unsafe { narf_pci_enable(dev_token, PCI_CMD_MEM_SPACE) } != 0 {
        return -5; // -EIO
    }

    let regs = ModuleRegisters {
        dev: dev_token,
        bar: bar0,
    };
    if super::hardware::reset(&regs, 4).is_err()
        || super::hardware::setup_phy(&regs, gigabit).is_err()
    {
        return -5;
    }
    let _status = match mmio_read(dev_token, bar0, IGC_STATUS) {
        Ok(value) if value != u32::MAX => value,
        _ => return -5,
    };
    let ral = match mmio_read(dev_token, bar0, IGC_RAL0) {
        Ok(value) => value,
        Err(errno) => return errno,
    };
    let rah = match mmio_read(dev_token, bar0, IGC_RAH0) {
        Ok(value) => value,
        Err(errno) => return errno,
    };
    if ral == 0 && (rah & 0xFFFF) == 0 {
        return -5;
    }
    let mac = [
        ral as u8,
        (ral >> 8) as u8,
        (ral >> 16) as u8,
        (ral >> 24) as u8,
        rah as u8,
        (rah >> 8) as u8,
    ];

    // Keep the Stage-2 stale-handle/range proof as a regression guard before
    // allocating the persistent rings.
    const PATTERN: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ];
    // SAFETY: C-ABI kernel export; `dev_token` belongs to this callback and
    // the requested allocation is non-zero and bounded by the kernel.
    let scratch = unsafe { narf_dma_alloc(dev_token, 64) };
    if scratch == 0 {
        return -12; // -ENOMEM
    }
    // SAFETY: `PATTERN` is readable for the duration of the call; the kernel
    // validates handle ownership and `[0, PATTERN.len())` before copying.
    if unsafe { narf_dma_write(dev_token, scratch, 0, PATTERN.as_ptr(), PATTERN.len()) } != 0 {
        return -5;
    }
    let mut observed = [0u8; PATTERN.len()];
    // SAFETY: `observed` is writable for the call; source bounds and handle
    // ownership are checked by the kernel.
    if unsafe { narf_dma_read(dev_token, scratch, 0, observed.as_mut_ptr(), observed.len()) } != 0
        || observed != PATTERN
    {
        return -5;
    }
    // A range whose end overflows must be rejected before copying.
    // SAFETY: `PATTERN` is readable; the deliberately invalid destination
    // offset exercises the kernel's checked range arithmetic.
    if unsafe {
        narf_dma_write(
            dev_token,
            scratch,
            u64::MAX - 7,
            PATTERN.as_ptr(),
            PATTERN.len(),
        )
    } == 0
    {
        return -5;
    }
    let mut dma_addr = 0u64;
    // SAFETY: `dma_addr` is writable and offset zero is inside the live DMA
    // allocation. The returned value is for device programming only.
    if unsafe { narf_dma_addr(dev_token, scratch, 0, &mut dma_addr) } != 0 || dma_addr == 0 {
        return -5;
    }
    // SAFETY: `scratch` is live and belongs to this device context.
    if unsafe { narf_dma_free(dev_token, scratch) } != 0 {
        return -5;
    }
    // A freed handle must fail closed.
    // SAFETY: the output pointer is valid; the stale handle is intentionally
    // supplied to test rejection and must not be dereferenced by the kernel.
    if unsafe { narf_dma_addr(dev_token, scratch, 0, &mut dma_addr) } == 0 {
        return -5;
    }

    if let Err(errno) = init_dma_rings(state, dev_token, bar0) {
        return errno;
    }
    // Allocating the persistent rings must not make the freed scratch handle
    // valid again. Opaque handles are monotonic for one device-context
    // lifetime, so stale module state cannot alias a newer DMA allocation.
    // SAFETY: the output pointer is writable; `scratch` was freed above and
    // must remain rejected even after subsequent allocations.
    if unsafe { narf_dma_addr(dev_token, scratch, 0, &mut dma_addr) } == 0 {
        return -5;
    }
    let ctrl = match mmio_read(dev_token, bar0, IGC_CTRL) {
        Ok(value) => value,
        Err(errno) => return errno,
    };
    if mmio_write(dev_token, bar0, IGC_CTRL, ctrl | CTRL_SLU).is_err() {
        return -5;
    }

    state.dev_token.store(dev_token, Ordering::Relaxed);
    state.bar0.store(bar0, Ordering::Relaxed);
    state.ready.store(true, Ordering::Release);

    let mut ifindex = 0u32;
    // SAFETY: `mac` and `ifindex` are live locals and `net_tx` remains mapped
    // until the context is torn down before module unmap.
    if unsafe {
        narf_netif_register_with_context(dev_token, mac.as_ptr(), net_tx as usize, &mut ifindex)
    } != 0
        || ifindex == 0
    {
        return -5;
    }
    state.ifindex.store(ifindex, Ordering::Release);

    // Stage-3 IRQ path. QEMU's legacy I225_LM model commonly has no MSI-X
    // capability, so `-EOPNOTSUPP` is an expected fallback to the periodic
    // poller. If MSI-X exists, claim a kernel vector and attach the module
    // callback; the actual NIC interrupt-mask programming arrives with the
    // Stage-4 descriptor rings.
    // SAFETY: `dev_token` is the live context passed by the kernel trampoline.
    let msix = unsafe { narf_msix_enable(dev_token) };
    if msix == 0 {
        let mut vector = 0u16;
        // SAFETY: `vector` is writable for the duration of the call.
        if unsafe { narf_msix_claim(dev_token, &mut vector) } != 0 {
            return -5;
        }
        // SAFETY: `datapath_poll` has the required C ABI and remains mapped
        // for the lifetime of this module-owned device context.
        if unsafe { narf_irq_set_handler(dev_token, vector, datapath_poll as usize, dev_token) }
            != 0
        {
            return -5;
        }
        for (reg, value) in [
            (0x1514, 0xc0000011),
            (0x1700, 0x8080),
            (0x1740, 0x8000),
            (0x1680, 0x80000288),
            (0x1524, 1),
        ] {
            if mmio_write(dev_token, bar0, reg, value).is_err() {
                return -5;
            }
        }
        if mmio_write(dev_token, bar0, IGC_IMS, IMS_DEFAULT).is_err() {
            return -5;
        }
    } else if msix != -95 {
        return msix;
    }

    // Always keep a low-rate periodic pump: it is the fallback on legacy
    // I225_LM and closes missed-edge/interrupt-masking gaps on MSI-X devices.
    // SAFETY: `datapath_poll` is valid module text until teardown.
    if unsafe { narf_spawn_poller(dev_token, datapath_poll as usize, dev_token) } != 0 {
        return -5;
    }

    log("igc(.ko): DMA rings + copy-mode netif live in selected frame\n");
    0
}

/// Register igc's primary match through the kernel ABI.
pub fn register() {
    const IDS: &[u16] = &[
        0x15f2, 0x15f3, 0x0d9f, 0x15f8, 0x15f7, 0x3100, 0x3101, 0x5502, 0x15fd, 0x125b, 0x125c,
        0x125d, 0x3102, 0x5503, 0x125f, 0x125e,
    ];
    for &id in IDS {
        let probe = if matches!(id, 0x15f7 | 0x125e) {
            probe_gigabit
        } else {
            probe_c
        };
        // SAFETY: static name, static C ABI callback; kernel scopes every token.
        unsafe {
            narf_register_pci_driver(b"igc".as_ptr(), 3, IGC_VENDOR, id, probe as usize);
        }
    }
}
#[derive(Debug)]
struct ModuleRegisters {
    dev: u64,
    bar: u64,
}
impl super::hardware::Registers for ModuleRegisters {
    fn note(&self, message: &'static str) {
        log("igc(.ko): ");
        log(message);
        log("\n");
    }
    fn read(&self, reg: u64) -> u32 {
        mmio_read(self.dev, self.bar, reg).unwrap_or(u32::MAX)
    }
    fn write(&self, reg: u64, value: u32) {
        let _ = mmio_write(self.dev, self.bar, reg, value);
    }
    fn wait(&self, us: u64, mut ready: impl FnMut() -> bool) -> bool {
        // SAFETY: monotonic clock is a pointer-free SDK call.
        let deadline = unsafe { narf_monotonic_ns() }.saturating_add(us.saturating_mul(1000));
        loop {
            if ready() {
                return true;
            }
            // SAFETY: pointer-free SDK clock read.
            let now = unsafe { narf_monotonic_ns() };
            if now >= deadline {
                break;
            }
            // SAFETY: SDK services pumps during a bounded impossible-condition delay.
            let _ = unsafe {
                narf_mmio_wait32(self.dev, self.bar, 8, 0, 1, (deadline - now).min(100_000))
            };
        }
        false
    }
    fn delay(&self, us: u64) {
        // SAFETY: responsive deadline wait on a condition that cannot become true.
        let _ = unsafe { narf_mmio_wait32(self.dev, self.bar, 8, 0, 1, us.saturating_mul(1000)) };
    }
}

/// The kernel stops callbacks before exit. Failed drains leave registry-held
/// DMA allocations quarantined even after module text/context destruction.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    for state in &DEVICES {
        state.ready.store(false, Ordering::Release);
        let dev = state.dev_token.load(Ordering::Acquire);
        let bar = state.bar0.load(Ordering::Acquire);
        if dev != 0
            && bar != 0
            && super::hardware::quiesce(&ModuleRegisters { dev, bar }, 1).is_ok()
        {
            // SAFETY: controller acknowledged all outstanding master transactions.
            let _ = unsafe { narf_dma_retain_on_teardown(dev, 0) };
        }
    }
}
