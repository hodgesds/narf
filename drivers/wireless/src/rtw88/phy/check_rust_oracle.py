"""Run unmodified native C21/C22 PHY callbacks against compiled Linux oracles.

The host shim supplies inert register bytes and immediately completed delays.
Kernel smokes cover bounded native ownership, current-policy errors and drop.
"""
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
source = r'''
#![allow(dead_code)]
extern crate self as narf_crypto;
pub mod sha256 {pub struct Sha256;impl Sha256{pub fn update(&mut self,_:&[u8]){}}}
mod rtw88 {
 pub mod efuse {
  pub struct Factory;impl Factory{pub fn rfe(&self)->u8{0}pub fn crystal(&self)->u8{0}pub fn board_option(&self)->u8{0}pub fn thermal(&self)->[u8;2]{[0;2]}}
  pub struct Factory8821c;impl Factory8821c{pub fn rfe(&self)->u8{0}pub fn crystal(&self)->u8{0}pub fn package(&self)->u8{0}}
 }
 pub mod hardware {#[derive(Clone,Copy)]pub struct Features{pub antennas:u8,pub streams:u8}}
 pub mod firmware_transport {
  #[derive(Debug)]pub enum Error{Unsupported,Gone}
  pub trait Io{fn read8(&mut self,r:u16)->Result<u8,Error>;fn read32(&mut self,r:u16)->Result<u32,Error>;fn write8(&mut self,r:u16,v:u8)->Result<(),Error>;fn write32(&mut self,r:u16,v:u32)->Result<(),Error>;async fn delay_us(&mut self,n:u64);}
 }
 #[path="C21_PATH"]pub mod phy8821c;
 #[path="C22_PATH"]pub mod phy;
 include!("C21_GOLDEN");include!("C22_GOLDEN");
 pub async fn check(){
  for(c,packages)in LINUX_C21_HASHES.iter().enumerate(){for(p,rfes)in packages.iter().enumerate(){for(r,kinds)in rfes.iter().enumerate(){
   let info=phy8821c::Info{cut:c as u8,package:p as u8,rfe:(r*2)as u8,crystal:0x33,channel_filters:[0;3]};
   for(k,want)in kinds.iter().enumerate(){let mut io=super::Model::new();phy8821c::apply_table(&mut io,info,k).await.unwrap();assert_eq!(io.hash(),*want,"C21 cut{c}/pkg{p}/RFE{r}/kind{k}");}
   let mut io=super::Model::new();let got=phy8821c::prepare(&mut io,info).await.unwrap();let want=LINUX_C21_PREFIX[c][p][r];assert_eq!((io.hash(),got.channel_filters),want,"C21 prefix cut{c}/pkg{p}/RFE{r}");
  }}}
  for(c,rfes)in LINUX_PHY_HASHES.iter().enumerate(){for(r,kinds)in rfes.iter().enumerate(){for(k,want)in kinds.iter().enumerate(){
   let info=phy::Info{cut:c as u8,rfe:r as u8,paths:2,crystal:0x33};let mut io=super::Model::new();phy::apply_table(&mut io,info,k).await.unwrap();assert_eq!(io.hash(),*want,"C22 cut{c}/RFE{r}/kind{k}");
  }}}
 }
}
use rtw88::firmware_transport::{Error,Io};
struct Model{regs:Vec<u8>,trace:Vec<(u8,u32,u32)>}
impl Model{fn new()->Self{Self{regs:(0..0x5000).map(|i|(i as u8).wrapping_mul(17).wrapping_add(7)).collect(),trace:vec![]}}
 fn hash(&self)->u64{let mut h=14695981039346656037u64;for&(k,r,v)in&self.trace{for b in std::iter::once(k).chain(r.to_le_bytes()).chain(v.to_le_bytes()){h=(h^b as u64).wrapping_mul(1099511628211);}}h}}
impl Io for Model{
 fn read8(&mut self,r:u16)->Result<u8,Error>{self.trace.push((4,r as u32,0));Ok(self.regs[r as usize])}
 fn read32(&mut self,r:u16)->Result<u32,Error>{self.trace.push((0,r as u32,0));Ok(u32::from_le_bytes(self.regs[r as usize..r as usize+4].try_into().unwrap()))}
 fn write8(&mut self,r:u16,v:u8)->Result<(),Error>{self.trace.push((3,r as u32,v as u32));self.regs[r as usize]=v;Ok(())}
 fn write32(&mut self,r:u16,v:u32)->Result<(),Error>{self.trace.push((1,r as u32,v));self.regs[r as usize..r as usize+4].copy_from_slice(&v.to_le_bytes());Ok(())}
 async fn delay_us(&mut self,n:u64){self.trace.push((2,0,n as u32));}
}
fn main(){use std::future::Future;let mut future=std::pin::pin!(rtw88::check());assert!(future.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())).is_ready());println!("56 C21 profiles: all five table callbacks and complete source prefix match; 49 C22 profiles unchanged");}
'''
for name, path in [('C21_PATH',HERE/'rtl8821c.rs'),('C22_PATH',HERE.parent/'phy.rs'),('C21_GOLDEN',HERE/'rtl8821c_golden.rs'),('C22_GOLDEN',HERE/'golden.rs')]:
    source = source.replace(name,str(path))
with tempfile.TemporaryDirectory() as temp:
    rust, exe = Path(temp)/'check.rs',Path(temp)/'check'
    rust.write_text(source)
    subprocess.run(['rustc','--edition','2021','-O',str(rust),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True)
