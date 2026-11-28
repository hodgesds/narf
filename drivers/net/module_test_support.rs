//! Host KABI/device model for the *compiled module* paths. Bus addresses are
//! deliberately unrelated to CPU pointers. Register layouts are checked
//! against Linux r8169_main.c / mlx4 (not driver encoder round trips).
#![allow(dead_code)]
extern crate std;
use core::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
    vec::Vec,
};
pub static CLOCK: AtomicU64 = AtomicU64::new(0);
pub static STEP: AtomicU64 = AtomicU64::new(100);
pub static MODEL: LazyLock<Mutex<Model>> = LazyLock::new(|| Mutex::new(Model::default()));
#[derive(Default)]
pub struct Model {
    pub vendor: u16,
    pub device: u16,
    pub regs: BTreeMap<(u64, u64), u32>,
    pub ocp: BTreeMap<u32, u16>,
    pub dma: BTreeMap<u64, (usize, usize)>,
    pub next_dma: u64,
    pub probe: usize,
    pub tx: usize,
    pub poll: usize,
    pub carrier: bool,
    pub firmware: Vec<u8>,
    pub fw_missing: bool,
    pub short_read: bool,
    pub closes: usize,
    pub fw_reads: Vec<(u64, usize)>,
    pub rx: Vec<Vec<u8>>,
    pub sent: Vec<Vec<u8>>,
    pub stuck_reset: bool,
    pub stuck_hcr: bool,
    pub stale_toggle: bool,
    pub fail_op: u16,
    pub commands: Vec<(u16, u32)>,
    pub mapped_fw_pages: usize,
    pub fw_pages: u16,
    pub freed: usize,
    pub retain: bool,
    pub auto_tx: bool,
    pub mtt: BTreeMap<u64, u64>,
    pub cq_cpu: usize,
    pub wq_cpu: usize,
    pub qp_context: Vec<u8>,
}
impl Model {
    pub fn reg(&self, bar: u64, off: u64) -> u32 {
        *self.regs.get(&(bar, off)).unwrap_or(&0)
    }
    pub fn ptr(&self, bus: u64) -> *mut u8 {
        let (&base, &(cpu, len)) = self
            .dma
            .range(..=bus)
            .next_back()
            .expect("unmapped DMA address");
        assert!(bus - base < len as u64, "DMA outside allocation");
        (cpu + (bus - base) as usize) as *mut u8
    }
    pub fn setup_realtek(&mut self) {
        self.vendor = 0x10ec;
        self.device = 0x8125;
        self.auto_tx = true;
        self.regs.insert((3, 0x40), 0x64100000);
        for (i, b) in [2u8, 1, 2, 3, 4, 5].iter().enumerate() {
            self.regs.insert((3, i as u64), u32::from(*b));
        }
        self.regs.insert((3, 0x6c), 2);
    }
    pub fn setup_mlx4(&mut self) {
        self.vendor = 0x15b3;
        self.device = 0x1003;
        self.fw_pages = 8193;
    }
    pub fn inject_rtl(&mut self, packet: &[u8], slot: usize, extra_flags: u32) {
        let ring = u64::from(self.reg(3, 0xe4)) | (u64::from(self.reg(3, 0xe8)) << 32);
        // SAFETY: model owns these mapped, aligned DMA allocations.
        unsafe {
            let d = self.ptr(ring).add(slot * 16).cast::<u32>();
            let buffer = u64::from(d.add(2).read()) | (u64::from(d.add(3).read()) << 32);
            core::ptr::copy_nonoverlapping(packet.as_ptr(), self.ptr(buffer), packet.len());
            d.write((3 << 28) | (packet.len() as u32 + 4) | extra_flags);
        }
    }
    fn hcr(&mut self, word: u32) {
        let op = (word & 0xfff) as u16;
        let modifier = self.reg(1, 0x80688).swap_bytes();
        self.commands.push((op, modifier));
        if self.stuck_hcr {
            return;
        }
        let input = (u64::from(self.reg(1, 0x80680).swap_bytes()) << 32)
            | u64::from(self.reg(1, 0x80684).swap_bytes());
        let output = (u64::from(self.reg(1, 0x8068c).swap_bytes()) << 32)
            | u64::from(self.reg(1, 0x80690).swap_bytes());
        let mut out = [0u8; 256];
        if op == 4 {
            out[0..2].copy_from_slice(&self.fw_pages.to_be_bytes());
            out[2..4].copy_from_slice(&2u16.to_be_bytes());
            out[4..6].copy_from_slice(&5000u16.to_be_bytes());
            out[6..8].copy_from_slice(&36u16.to_be_bytes());
        }
        if op == 3 {
            out[0x11] = 12;
            out[0x13] = 20;
            out[0x19] = 16;
            out[0x1b] = 20;
            out[0x1d] = 20;
            out[0x1f] = 8;
            out[0x37] = 1;
            for (off, size) in [
                (0x80, 32u16),
                (0x82, 256),
                (0x84, 64),
                (0x86, 64),
                (0x88, 64),
                (0x8a, 64),
                (0x8e, 32),
                (0x90, 8),
                (0x92, 64),
            ] {
                out[off..off + 2].copy_from_slice(&size.to_be_bytes());
            }
        }
        if op == 0x43 {
            out[0] = 0x80;
            out[0x12..0x18].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
        }
        // SAFETY: command fields refer to allocations registered by this model.
        unsafe {
            if [3, 4, 6, 0x43].contains(&op) {
                core::ptr::copy_nonoverlapping(out.as_ptr(), self.ptr(output), out.len());
            }
            if op == 0xfff {
                assert!((1..=256).contains(&modifier));
                for i in 0..modifier as usize {
                    let bus = be64(core::slice::from_raw_parts(
                        self.ptr(input).add(i * 16 + 8),
                        8,
                    ));
                    assert!(!self.ptr(bus).is_null());
                }
                self.mapped_fw_pages += modifier as usize;
            }
            if op == 0xffd {
                self.regs.insert((1, 0x8068c), 0);
                self.regs.insert((1, 0x80690), 1u32.to_be());
            }
            if op == 0x11 {
                let bytes =
                    core::slice::from_raw_parts(self.ptr(input), 16 + modifier as usize * 8);
                let base = be64(&bytes[0..8]);
                for i in 0..modifier as usize {
                    self.mtt.insert(
                        (base + i as u64) * 8,
                        be64(&bytes[16 + i * 8..24 + i * 8]) & !1,
                    );
                }
            }
            if op == 0x16 {
                let bytes = core::slice::from_raw_parts(self.ptr(input), 64);
                let mtt = (u64::from(bytes[0x1b]) << 32) | u64::from(be32(&bytes[0x1c..0x20]));
                self.cq_cpu = self.ptr(self.mtt[&mtt]) as usize;
                assert_eq!(
                    *(self.cq_cpu as *const u8).add(31),
                    0x80,
                    "empty CQ must be HW-owned"
                );
            }
            if op == 0x19 {
                let ctx = core::slice::from_raw_parts(self.ptr(input).add(8), 256);
                self.qp_context = ctx.to_vec();
                let mtt = (u64::from(ctx[0xab]) << 32) | u64::from(be32(&ctx[0xac..0xb0]));
                self.wq_cpu = self.ptr(self.mtt[&mtt]) as usize;
            }
        }
        let mut status = word & (1 << 21);
        if self.stale_toggle {
            status ^= 1 << 21;
        }
        if self.fail_op == op {
            status |= 3 << 24;
        }
        self.regs.insert((1, 0x80698), status.to_be());
    }
}
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}
pub fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}
#[unsafe(no_mangle)]
extern "C" fn narf_monotonic_ns() -> u64 {
    CLOCK.fetch_add(STEP.load(Ordering::Relaxed), Ordering::Relaxed)
}
#[unsafe(no_mangle)]
extern "C" fn narf_udelay(ns: u64) -> i32 {
    CLOCK.fetch_add(ns, Ordering::Relaxed);
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_printk(p: *const u8, n: usize) -> i32 {
    // SAFETY: caller passes a live console string.
    std::eprint!(
        "{}",
        // SAFETY: the driver console provides a readable string for this synchronous call.
        std::string::String::from_utf8_lossy(unsafe { core::slice::from_raw_parts(p, n) })
    );
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_register_pci_driver(
    _: *const u8,
    _: usize,
    _: u16,
    _: u16,
    probe: usize,
) -> i32 {
    MODEL.lock().unwrap().probe = probe;
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_pci_identity(_: u64, p: *mut u8, n: usize) -> i32 {
    assert_eq!(n, 16);
    let m = MODEL.lock().unwrap();
    // SAFETY: caller supplies 16 bytes.
    unsafe {
        core::ptr::write_bytes(p, 0, 16);
        core::ptr::copy_nonoverlapping(m.vendor.to_le_bytes().as_ptr(), p, 2);
        core::ptr::copy_nonoverlapping(m.device.to_le_bytes().as_ptr(), p.add(2), 2);
    }
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_pci_prepare_probe(_: u64) -> i32 {
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_dma_retain_on_teardown(_: u64, r: u32) -> i32 {
    MODEL.lock().unwrap().retain = r != 0;
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_pci_command(_: u64, _: u16, set: u16, out: *mut u16) -> i32 {
    // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
    unsafe {
        out.write(set);
    }
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_bar_map_control(_: u64, bar: u8) -> u64 {
    u64::from(bar) + 1
}
fn read(bar: u64, off: u64) -> u32 {
    MODEL.lock().unwrap().reg(bar, off)
}
fn write(bar: u64, off: u64, value: u32, width: usize) {
    let mut m = MODEL.lock().unwrap();
    m.regs.insert((bar, off), value);
    if m.vendor == 0x10ec {
        if off == 0x37 && value & 0x10 != 0 && !m.stuck_reset {
            m.regs.insert((bar, off), 0);
        }
        if off == 0x80 || off == 0xb8 {
            let addr = if off == 0xb8 {
                (value >> 15) & 0xffff
            } else {
                (value >> 16) & 0x7fff
            };
            if value & 0x80000000 != 0 {
                m.ocp.insert(addr, value as u16);
                m.regs.insert((bar, off), value & !0x80000000);
            } else {
                let data = u32::from(*m.ocp.get(&addr).unwrap_or(&0));
                m.regs.insert((bar, off), 0x80000000 | data);
            }
        }
        if off == 0xb0 {
            let addr = (value >> 15) & 0xffff;
            if value & 0x80000000 != 0 {
                m.ocp.insert(addr, value as u16);
            } else {
                let data = u32::from(*m.ocp.get(&addr).unwrap_or(&0));
                m.regs.insert((bar, off), data);
            }
        }
        if off == 0x90 && width == 2 && value == 1 && m.auto_tx {
            let ring = u64::from(m.reg(3, 0x20)) | (u64::from(m.reg(3, 0x24)) << 32);
            // SAFETY: descriptors/payload are model-owned mapped allocations.
            unsafe {
                for slot in 0..256 {
                    let d = m.ptr(ring).add(slot * 16).cast::<u32>();
                    let flags = d.read();
                    if flags >> 31 == 0 {
                        continue;
                    }
                    let bus = u64::from(d.add(2).read()) | (u64::from(d.add(3).read()) << 32);
                    let frame =
                        core::slice::from_raw_parts(m.ptr(bus), (flags & 0x3fff) as usize).to_vec();
                    m.sent.push(frame);
                    d.write(flags & !(1 << 31));
                }
            }
        }
    } else if bar == 1 && off == 0x80698 {
        m.hcr(value.swap_bytes());
    }
}
macro_rules! mmio {
    ($read:ident,$write:ident,$ty:ty) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $read(_: u64, b: u64, o: u64, p: *mut $ty) -> i32 {
            // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
            unsafe {
                p.write(read(b, o) as $ty);
            }
            0
        }
        #[unsafe(no_mangle)]
        extern "C" fn $write(_: u64, b: u64, o: u64, v: $ty) -> i32 {
            write(b, o, u32::from(v), core::mem::size_of::<$ty>());
            0
        }
    };
}
mmio!(narf_mmio_read8, narf_mmio_write8, u8);
mmio!(narf_mmio_read16, narf_mmio_write16, u16);
mmio!(narf_mmio_read32, narf_mmio_write32, u32);
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_dma_alloc_mapped(
    _: u64,
    len: usize,
    _: u32,
    cpu: *mut usize,
    bus: *mut u64,
    reserved: *mut usize,
) -> u64 {
    let layout = std::alloc::Layout::from_size_align(len, 4096).unwrap();
    // SAFETY: nonzero driver DMA length and valid alignment.
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!ptr.is_null());
    let mut m = MODEL.lock().unwrap();
    let address = 0x100000000 + m.next_dma;
    m.next_dma += len.next_multiple_of(4096) as u64;
    m.dma.insert(address, (ptr as usize, len));
    // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
    unsafe {
        cpu.write(ptr as usize);
        bus.write(address);
        reserved.write(len);
    }
    address
}
#[unsafe(no_mangle)]
extern "C" fn narf_dma_free(_: u64, handle: u64) -> i32 {
    let mut m = MODEL.lock().unwrap();
    let (cpu, len) = m.dma.remove(&handle).expect("double free");
    m.freed += 1;
    // SAFETY: matching allocation removed from the live map.
    unsafe {
        std::alloc::dealloc(
            cpu as *mut u8,
            std::alloc::Layout::from_size_align(len, 4096).unwrap(),
        );
    }
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_spawn_poller(_: u64, cb: usize, _: u64) -> i32 {
    MODEL.lock().unwrap().poll = cb;
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_netif_register_with_context(
    _: u64,
    _: *const u8,
    tx: usize,
    index: *mut u32,
) -> i32 {
    MODEL.lock().unwrap().tx = tx;
    // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
    unsafe {
        index.write(1);
    }
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_netif_set_link(_: u64, _: u32, c: u32) -> i32 {
    MODEL.lock().unwrap().carrier = c != 0;
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_netif_rx(_: u64, _: u32, p: *mut u8, n: usize) -> i32 {
    MODEL
        .lock()
        .unwrap()
        .rx
        // SAFETY: the driver supplies n live frame bytes; the model copies them before returning.
        .push(unsafe { core::slice::from_raw_parts(p, n) }.to_vec());
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_firmware_open(
    _: *const u8,
    _: usize,
    h: *mut u64,
    size: *mut usize,
) -> i32 {
    let m = MODEL.lock().unwrap();
    if m.fw_missing {
        return -2;
    }
    // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
    unsafe {
        h.write(1);
        size.write(m.firmware.len());
    }
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn narf_firmware_read(
    _: u64,
    offset: u64,
    p: *mut u8,
    n: usize,
    copied: *mut usize,
) -> i32 {
    assert!(n <= 65536);
    let mut m = MODEL.lock().unwrap();
    m.fw_reads.push((offset, n));
    if m.short_read {
        // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
        unsafe {
            copied.write(0);
        }
        return 0;
    }
    let source = &m.firmware[offset as usize..offset as usize + n];
    // SAFETY: this mock implements the KABI contract; the driver supplies live, aligned outputs and in-bounds buffers.
    unsafe {
        core::ptr::copy_nonoverlapping(source.as_ptr(), p, n);
        copied.write(n);
    }
    0
}
#[unsafe(no_mangle)]
extern "C" fn narf_firmware_close(_: u64) -> i32 {
    MODEL.lock().unwrap().closes += 1;
    0
}
pub fn probe(token: u64) -> i32 {
    let address = MODEL.lock().unwrap().probe;
    // SAFETY: address was registered by this driver with exactly this C callback signature.
    let callback: extern "C" fn(u64, u64) -> i32 = unsafe { core::mem::transmute(address) };
    callback(token, 0)
}
pub fn poll(token: u64) -> i32 {
    let address = MODEL.lock().unwrap().poll;
    // SAFETY: address was registered by this driver with exactly this C callback signature.
    let callback: extern "C" fn(u64) -> i32 = unsafe { core::mem::transmute(address) };
    callback(token)
}
pub fn transmit(token: u64, frame: &[u8]) -> i32 {
    let address = MODEL.lock().unwrap().tx;
    let callback: extern "C" fn(u64, *const u8, usize) -> i32 =
        // SAFETY: address was registered by this driver with exactly this C callback signature.
        unsafe { core::mem::transmute(address) };
    callback(token, frame.as_ptr(), frame.len())
}
