//! Execute a VBIOS command table through NARF's ATOM interpreter
//! (`drivers/gpu/src/amdgpu_atom_vm.rs`, included verbatim) against a
//! recording fake register bus, as `amdgpu_atom_asic_init` would on the
//! card, and report every opcode, table, IIO port and register used.
//!
//! The fake bus returns the last value written to a register (0, or a
//! `--set` value, before that). Polling loops on hardware status bits
//! therefore spin until atom.c's 20 s same-jump guard fires on the fake
//! clock (1 µs per register access plus the DELAY requests); the report
//! names the table, offset and the registers polled, and `--set` can
//! preload the expected status to continue past them.
//!
//! Usage: atom-trace <vbios.rom> [--table N] [--set REG=VALUE]... [--trace]
//!        [--max-steps N]
extern crate alloc;

#[allow(dead_code, clippy::all)]
#[path = "../../../src/amdgpu_atom_vm.rs"]
mod amdgpu_atom_vm;

use amdgpu_atom_vm::{AtomState, Hooks, Machine, ResolvedTable, Step};
use std::collections::BTreeMap;
use std::process::ExitCode;

/// atom.c `atom_op_names`.
const OP_NAMES: [&str; 127] = [
    "RESERVED",
    "MOVE_REG",
    "MOVE_PS",
    "MOVE_WS",
    "MOVE_FB",
    "MOVE_PLL",
    "MOVE_MC",
    "AND_REG",
    "AND_PS",
    "AND_WS",
    "AND_FB",
    "AND_PLL",
    "AND_MC",
    "OR_REG",
    "OR_PS",
    "OR_WS",
    "OR_FB",
    "OR_PLL",
    "OR_MC",
    "SHIFT_LEFT_REG",
    "SHIFT_LEFT_PS",
    "SHIFT_LEFT_WS",
    "SHIFT_LEFT_FB",
    "SHIFT_LEFT_PLL",
    "SHIFT_LEFT_MC",
    "SHIFT_RIGHT_REG",
    "SHIFT_RIGHT_PS",
    "SHIFT_RIGHT_WS",
    "SHIFT_RIGHT_FB",
    "SHIFT_RIGHT_PLL",
    "SHIFT_RIGHT_MC",
    "MUL_REG",
    "MUL_PS",
    "MUL_WS",
    "MUL_FB",
    "MUL_PLL",
    "MUL_MC",
    "DIV_REG",
    "DIV_PS",
    "DIV_WS",
    "DIV_FB",
    "DIV_PLL",
    "DIV_MC",
    "ADD_REG",
    "ADD_PS",
    "ADD_WS",
    "ADD_FB",
    "ADD_PLL",
    "ADD_MC",
    "SUB_REG",
    "SUB_PS",
    "SUB_WS",
    "SUB_FB",
    "SUB_PLL",
    "SUB_MC",
    "SET_ATI_PORT",
    "SET_PCI_PORT",
    "SET_SYS_IO_PORT",
    "SET_REG_BLOCK",
    "SET_FB_BASE",
    "COMPARE_REG",
    "COMPARE_PS",
    "COMPARE_WS",
    "COMPARE_FB",
    "COMPARE_PLL",
    "COMPARE_MC",
    "SWITCH",
    "JUMP",
    "JUMP_EQUAL",
    "JUMP_BELOW",
    "JUMP_ABOVE",
    "JUMP_BELOW_OR_EQUAL",
    "JUMP_ABOVE_OR_EQUAL",
    "JUMP_NOT_EQUAL",
    "TEST_REG",
    "TEST_PS",
    "TEST_WS",
    "TEST_FB",
    "TEST_PLL",
    "TEST_MC",
    "DELAY_MILLISEC",
    "DELAY_MICROSEC",
    "CALL_TABLE",
    "REPEAT",
    "CLEAR_REG",
    "CLEAR_PS",
    "CLEAR_WS",
    "CLEAR_FB",
    "CLEAR_PLL",
    "CLEAR_MC",
    "NOP",
    "EOT",
    "MASK_REG",
    "MASK_PS",
    "MASK_WS",
    "MASK_FB",
    "MASK_PLL",
    "MASK_MC",
    "POST_CARD",
    "BEEP",
    "SAVE_REG",
    "RESTORE_REG",
    "SET_DATA_BLOCK",
    "XOR_REG",
    "XOR_PS",
    "XOR_WS",
    "XOR_FB",
    "XOR_PLL",
    "XOR_MC",
    "SHL_REG",
    "SHL_PS",
    "SHL_WS",
    "SHL_FB",
    "SHL_PLL",
    "SHL_MC",
    "SHR_REG",
    "SHR_PS",
    "SHR_WS",
    "SHR_FB",
    "SHR_PLL",
    "SHR_MC",
    "DEBUG",
    "PROCESSDS",
    "MUL32_PS",
    "MUL32_WS",
    "DIV32_PS",
    "DIV32_WS",
];
/// BAR5 on Navi22 is 1 MiB; Linux reaches registers past it through
/// PCIE_INDEX2/PCIE_DATA2 (`amdgpu_device_indirect_rreg`).
const BAR_DWORDS: u32 = 0x4_0000;

#[derive(Default, Clone, Copy)]
struct Use {
    reads: u64,
    writes: u64,
    first_read: Option<u32>,
    last_write: Option<u32>,
}

struct Rom<'a> {
    bios: &'a [u8],
    cmd: usize,
    data: usize,
}
impl<'a> Rom<'a> {
    fn u8(&self, at: usize) -> Option<u8> {
        self.bios.get(at).copied()
    }
    fn u16(&self, at: usize) -> Option<usize> {
        let b = self.bios.get(at..at + 2)?;
        Some(usize::from(u16::from_le_bytes([b[0], b[1]])))
    }
    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.bios.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn parse(bios: &'a [u8]) -> Result<Self, String> {
        if bios.get(..2) != Some(&[0x55, 0xaa]) {
            return Err("no 55 AA PCI ROM signature".into());
        }
        let rom = Rom {
            bios,
            cmd: 0,
            data: 0,
        };
        let header = rom.u16(0x48).ok_or("short image")?;
        if bios.get(header + 4..header + 8) != Some(b"ATOM") {
            return Err("no ATOM ROM header".into());
        }
        Ok(Rom {
            bios,
            cmd: rom.u16(header + 0x1e).ok_or("no command directory")?,
            data: rom.u16(header + 0x20).ok_or("no data directory")?,
        })
    }
    fn command(&self, id: u8) -> usize {
        self.u16(self.cmd + 4 + 2 * usize::from(id)).unwrap_or(0)
    }
    fn data_table(&self, index: usize) -> usize {
        self.u16(self.data + 4 + 2 * index).unwrap_or(0)
    }
    fn table(&self, id: u8) -> Option<ResolvedTable<'a>> {
        let start = self.command(id);
        if start == 0 {
            return None;
        }
        let len = self.u16(start)?;
        let body = self.bios.get(start + 6..start + len.max(6))?;
        Some(ResolvedTable {
            body,
            ps_dwords: usize::from(self.u8(start + 5)? & 0x7f) / 4,
            start,
            ws_dwords: Some(usize::from(self.u8(start + 4)?)),
        })
    }
}

struct Bus<'r, 'a> {
    rom: &'r Rom<'a>,
    regs: BTreeMap<u32, u32>,
    uses: BTreeMap<u32, Use>,
    order: Vec<(bool, u32, u32)>,
    clock_us: u64,
}
impl<'a> Hooks<'a> for Bus<'_, 'a> {
    fn reg_read(&mut self, index: u32) -> u32 {
        self.clock_us += 1;
        let value = *self.regs.get(&index).unwrap_or(&0);
        let entry = self.uses.entry(index).or_default();
        entry.reads += 1;
        entry.first_read.get_or_insert(value);
        if self.order.len() < 1 << 20 {
            self.order.push((false, index, value));
        }
        value
    }
    fn reg_write(&mut self, index: u32, value: u32) {
        self.clock_us += 1;
        self.regs.insert(index, value);
        let entry = self.uses.entry(index).or_default();
        entry.writes += 1;
        entry.last_write = Some(value);
        if self.order.len() < 1 << 20 {
            self.order.push((true, index, value));
        }
    }
    fn resolve(&mut self, id: u8) -> Option<ResolvedTable<'a>> {
        self.rom.table(id)
    }
    fn table_absent(&mut self, id: u8) -> bool {
        self.rom.command(id) == 0
    }
    fn now_ms(&mut self) -> Option<u64> {
        Some(self.clock_us / 1000)
    }
}

fn number(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut path = None;
    let mut table = 0u8;
    let mut sets = Vec::new();
    let mut trace = false;
    let mut max_steps = 50_000_000u64;
    let mut i = 0;
    while i < args.len() {
        let next = |i: usize| args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--table" => {
                table = number(&next(i)).unwrap_or(0) as u8;
                i += 1;
            }
            "--set" => {
                let spec = next(i);
                let parsed = spec
                    .split_once('=')
                    .and_then(|(r, v)| Some((number(r)? as u32, number(v)? as u32)));
                match parsed {
                    Some(pair) => sets.push(pair),
                    None => {
                        eprintln!("bad --set {spec}; use REG=VALUE (dword index)");
                        return ExitCode::FAILURE;
                    }
                }
                i += 1;
            }
            "--max-steps" => {
                max_steps = number(&next(i)).unwrap_or(max_steps);
                i += 1;
            }
            "--trace" => trace = true,
            other => path = Some(other.to_string()),
        }
        i += 1;
    }
    let Some(path) = path else {
        eprintln!("usage: atom-trace <vbios.rom> [--table N] [--set REG=VALUE]... [--trace] [--max-steps N]");
        return ExitCode::FAILURE;
    };
    let bios = match std::fs::read(&path) {
        Ok(bios) => bios,
        Err(error) => {
            eprintln!("{path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let rom = match Rom::parse(&bios) {
        Ok(rom) => rom,
        Err(error) => {
            eprintln!("{path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    // amdgpu_atom_asic_init: PS[0]/PS[1] from FirmwareInfo (data table 4).
    let fwi = rom.data_table(4);
    let mut ps = [0u32; 16];
    if table == 0 {
        ps[0] = rom.u32(fwi + 8).unwrap_or(0);
        ps[1] = rom.u32(fwi + 12).unwrap_or(0);
        println!(
            "FirmwareInfo @ {fwi:#06x} rev {}.{}: default sclk {:#010x} ({} MHz), mclk {:#010x} ({} MHz), bios_scratch_reg_startaddr {:#x}",
            rom.u8(fwi + 2).unwrap_or(0),
            rom.u8(fwi + 3).unwrap_or(0),
            ps[0],
            (ps[0] & 0xff_ffff) / 100,
            ps[1],
            (ps[1] & 0xff_ffff) / 100,
            rom.u32(fwi + 0x18).unwrap_or(0),
        );
        if ps[0] == 0 || ps[1] == 0 {
            println!("warning: amdgpu_atom_asic_init would return 1 (zero default clock)");
        }
    }
    let start = rom.command(table);
    if start == 0 {
        eprintln!("command table {table} is absent");
        return ExitCode::FAILURE;
    }
    println!(
        "command table {table} @ {start:#06x}: size {}, rev {}.{}, WS {}, PS {} bytes",
        rom.u16(start).unwrap_or(0),
        rom.u8(start + 2).unwrap_or(0),
        rom.u8(start + 3).unwrap_or(0),
        rom.u8(start + 4).unwrap_or(0),
        rom.u8(start + 5).unwrap_or(0) & 0x7f,
    );
    let starts: BTreeMap<usize, u8> = (0..=255u8)
        .map(|id| (rom.command(id), id))
        .filter(|&(at, _)| at != 0)
        .collect();
    // amdgpu_atomfirmware_allocate_fb_scratch: 20 KiB unless vram_usage says.
    let fb_words = 20 * 1024 / 4;
    let bus = Bus {
        rom: &rom,
        regs: sets.iter().copied().collect(),
        uses: BTreeMap::new(),
        order: Vec::new(),
        clock_us: 0,
    };
    let mut state = AtomState::with_hooks(1, fb_words, bus);
    state.bios = &bios;
    state.data_table = rom.data;
    let mut machine = match Machine::start(&mut state, table, &mut ps) {
        Ok(machine) => machine,
        Err(error) => {
            eprintln!("start: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    let mut ops = [0u64; 127];
    let mut tables: BTreeMap<u8, u64> = BTreeMap::new();
    let mut ports: BTreeMap<u32, u64> = BTreeMap::new();
    let mut delay_us = 0u64;
    let mut last_table = None;
    let result = loop {
        if machine.steps() >= max_steps {
            break Err(format!("step limit {max_steps}"));
        }
        let step = machine.step(&mut state);
        if let Some(site) = machine.last() {
            ops[usize::from(site.opcode).min(126)] += 1;
            if last_table != Some(site.table_start) {
                last_table = Some(site.table_start);
                let id = starts.get(&site.table_start).copied().unwrap_or(0xff);
                *tables.entry(id).or_default() += 1;
            }
            if trace {
                let name = OP_NAMES.get(usize::from(site.opcode)).unwrap_or(&"?");
                println!(
                    "{:>width$}table {:#06x} +{:#06x} {name}",
                    "",
                    site.table_start,
                    site.offset + 6,
                    width = site.depth as usize * 2
                );
            }
        }
        if state.io_mode & 0x80 != 0 {
            *ports.entry(state.io_mode & 0x7f).or_default() += 1;
        }
        match step {
            Ok(Step::Continue) => {}
            Ok(Step::Delay(us)) => {
                delay_us += us;
                state.hooks.clock_us += us;
            }
            Ok(Step::Done) => break Ok(()),
            Err(error) => break Err(format!("{error:?} at {:?}", machine.last())),
        }
    };
    println!();
    match &result {
        Ok(()) => println!("result: EOT after {} opcodes", machine.steps()),
        Err(error) => println!("result: FAILED {error} after {} opcodes", machine.steps()),
    }
    println!(
        "delays requested: {delay_us} us; fake clock {} ms; anomalies {} (first {:?})",
        state.hooks.clock_us / 1000,
        state.anomalies,
        state.first_anomaly
    );
    println!("\nopcodes used:");
    for (op, count) in ops.iter().enumerate().filter(|(_, c)| **c != 0) {
        println!("  {op:3} {:<22} {count}", OP_NAMES[op]);
    }
    println!("\ncommand tables entered (id: entries):");
    for (id, count) in &tables {
        println!("  {id:3}: {count}");
    }
    println!("\nIIO ports (SET_ATI_PORT, opcodes executed while selected):");
    let iio = state.iio.clone().unwrap_or_default();
    for (port, count) in &ports {
        let read = iio.get(*port as usize).copied().unwrap_or(0);
        let write = iio.get(*port as usize | 0x80).copied().unwrap_or(0);
        println!(
            "  port {port:#x}: {count} (read program {read:#06x}, write program {write:#06x})"
        );
    }
    println!("\nregisters (dword index: reads, writes, first read, last write):");
    for (reg, used) in &state.hooks.uses {
        let path = if *reg >= BAR_DWORDS {
            " [indirect]"
        } else {
            ""
        };
        println!(
            "  {reg:#07x}{path}: r{} w{} first {} last {}",
            used.reads,
            used.writes,
            used.first_read.map_or("-".into(), |v| format!("{v:#010x}")),
            used.last_write.map_or("-".into(), |v| format!("{v:#010x}")),
        );
    }
    if trace {
        println!("\naccess order:");
        for (write, reg, value) in &state.hooks.order {
            println!(
                "  {} {reg:#07x} {value:#010x}",
                if *write { "W" } else { "R" }
            );
        }
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
