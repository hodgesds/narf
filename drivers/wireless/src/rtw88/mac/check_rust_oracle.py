"""Run unmodified production Rust MAC code against original-Linux C traces.

The host wrapper supplies only register storage, the LLT/pointer receipts and
a no-expiry clock for the immediate-success path. Kernel smokes separately
exercise actual deadlines, retained firmware ownership, failures and cancellation.
"""
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).parent
source = r'''
#![allow(dead_code)]
extern crate self as narf_time;
pub struct Deadline;
impl Deadline { pub fn after_ms(_:u64)->Self{Self} pub fn expired(&self)->bool{false} }
mod rtw88 {
  pub mod firmware_transport {
    #[derive(Debug,PartialEq,Eq)] pub enum Error {Access,Gone,Timeout,Unsupported,Prerequisite}
    pub trait Io {
      fn read8(&mut self,r:u16)->Result<u8,Error>;
      fn read16(&mut self,r:u16)->Result<u16,Error>;
      fn read32(&mut self,r:u16)->Result<u32,Error>;
      fn write8(&mut self,r:u16,v:u8)->Result<(),Error>;
      fn write16(&mut self,r:u16,v:u16)->Result<(),Error>;
      fn write32(&mut self,r:u16,v:u32)->Result<(),Error>;
      async fn delay_us(&mut self,n:u64);
    }
  }
  #[path = "MAC_PATH"] pub mod mac;
  pub async fn prepare(io:&mut impl firmware_transport::Io,did:u16)->Result<mac::Info,firmware_transport::Error>{mac::prepare_for(io,did).await}
}
use rtw88::firmware_transport::{Error,Io};
type Op=(u8,u8,u16,u32);
struct Model { regs:Vec<u8>, trace:Vec<Op> }
impl Model {
 fn new(seed:u8,cut:u8)->Self {
   let mut regs=(0..0x5000).map(|i|(i as u8).wrapping_mul(17).wrapping_add(seed.wrapping_mul(83))).collect::<Vec<_>>();
   regs[0xf0..0xf4].copy_from_slice(&(u32::from(cut)<<12).to_le_bytes());Self{regs,trace:Vec::new()}
 }
 fn read(&mut self,w:u8,r:u16)->u32 {
   self.trace.push((0,w,r,0));let mut bytes=[0;4];let at=r as usize;let n=w as usize/8;
   bytes[..n].copy_from_slice(&self.regs[at..at+n]);let v=u32::from_le_bytes(bytes);if r==0x208{v&!1}else{v}
 }
 fn write(&mut self,w:u8,r:u16,v:u32) {
   self.trace.push((1,w,r,v));let at=r as usize;let n=w as usize/8;
   self.regs[at..at+n].copy_from_slice(&v.to_le_bytes()[..n]);
   if r==0x254 && v&4!=0 {
     let head=u32::from_le_bytes(self.regs[0x244..0x248].try_into().unwrap())&0x3ffff;
     self.regs[0x10d0..0x10d4].copy_from_slice(&head.to_le_bytes());
     self.regs[0x10d4..0x10d8].copy_from_slice(&head.to_le_bytes());
   }
 }
}
impl Io for Model {
 fn read8(&mut self,r:u16)->Result<u8,Error>{Ok(self.read(8,r) as u8)}
 fn read16(&mut self,r:u16)->Result<u16,Error>{Ok(self.read(16,r) as u16)}
 fn read32(&mut self,r:u16)->Result<u32,Error>{Ok(self.read(32,r))}
 fn write8(&mut self,r:u16,v:u8)->Result<(),Error>{self.write(8,r,v as u32);Ok(())}
 fn write16(&mut self,r:u16,v:u16)->Result<(),Error>{self.write(16,r,v as u32);Ok(())}
 fn write32(&mut self,r:u16,v:u32)->Result<(),Error>{self.write(32,r,v);Ok(())}
 async fn delay_us(&mut self,n:u64){self.trace.push((8,0,0,n as u32));}
}
include!("GOLDEN22_PATH");
include!("GOLDEN21_PATH");
fn run(did:u16,seed:u8,cut:u8,expected:&[Op]) {
 use std::future::Future;
 let mut io=Model::new(seed,cut);
 let value={let mut fut=std::pin::pin!(rtw88::prepare(&mut io,did));
   match fut.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())){
     std::task::Poll::Ready(v)=>v.unwrap(),std::task::Poll::Pending=>panic!("immediate native receipt suspended")}};
 if io.trace!=expected {
   for (i,(got,want)) in io.trace.iter().zip(expected).enumerate(){if got!=want{eprintln!("{did:x} op{i}: got{got:?} want{want:?}");break;}}
   panic!("{did:x}: {} Rust vs {} Linux ops",io.trace.len(),expected.len());
 }
 assert_eq!(value.reserved_boundary,if did==0xc821{460}else{1938});
 assert_eq!(io.regs[0x100]&0xcf,0);assert_eq!(io.regs[0x522],255);
 println!("{did:04x} seed{seed}/cut{cut}: {} native Rust accesses match original Linux",expected.len());
}
fn main(){run(0xc821,0,0,LINUX_8821C_MAC_0);run(0xc821,1,3,LINUX_8821C_MAC_1);
run(0xc822,0,0,LINUX_MAC_0);run(0xc822,1,3,LINUX_MAC_1);}
'''.replace('MAC_PATH', str(HERE.parent / 'mac.rs')).replace(
    'GOLDEN22_PATH', str(HERE / 'golden.rs')).replace(
    'GOLDEN21_PATH', str(HERE / 'rtl8821c_golden.rs'))
with tempfile.TemporaryDirectory() as temp:
    rust, exe = Path(temp) / 'check.rs', Path(temp) / 'check'
    rust.write_text(source)
    subprocess.run(['rustc', '--edition', '2021', '-O', str(rust), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
