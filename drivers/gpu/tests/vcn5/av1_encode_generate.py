#!/usr/bin/env python3
"""Reproduce original AV1 encoder/parser fixtures with pinned libaom3.13.1.
Use an unchanged generic-CPU aomenc build. The native encoder model does not
implement AV1; independently decoded bytes are only fixture/oracle evidence.
"""
from pathlib import Path
import argparse,subprocess
p=argparse.ArgumentParser();p.add_argument('aomenc',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=a.out;r.mkdir(parents=True,exist_ok=True);w,h=320,128
source=bytes(32 if x<w//2 and y<h//2 else 80 if y<h//2 else 144 if x<w//2 else 208 for y in range(h)for x in range(w))+bytes([64])*(w*h//4)+bytes([192])*(w*h//4);(r/'input.i420').write_bytes(source)
def frame(data):
 data=data[44:];at=0
 while at<len(data):
  start=at;header=data[at];at+=1;n=0;shift=0
  while True:
   v=data[at];at+=1;n|=(v&127)<<shift;shift+=7
   if v<128:break
  end=at+n
  if (header>>3)&15==6:return data[start:end]
  at=end
 raise ValueError('missing frame')
for qp,name in [(0,'parser-lossless.obu'),(1,'reference-frame.obu'),(20,'parser-q20.obu')]:
 flags=['--codec=av1','--profile=0','--width=320','--height=128','--fps=1/1','--limit=1','--passes=1','--threads=1','--cpu-used=0','--lag-in-frames=0','--end-usage=q','--cq-level='+str(qp),'--lossless='+('1'if qp==0 else'0'),'--kf-max-dist=0','--kf-min-dist=0','--sb-size=64','--enable-order-hint=0','--enable-cdef=0','--enable-restoration=0','--enable-filter-intra=0','--enable-intra-edge-filter=0','--enable-dual-filter=0','--enable-ref-frame-mvs=0','--enable-global-motion=0','--enable-warped-motion=0','--enable-interintra-comp=0','--enable-masked-comp=0','--enable-obmc=0','--enable-palette=0','--enable-intrabc=0','--enable-qm=0','--deltaq-mode=0','--delta-lf-mode=0','--cdf-update-mode=0','--tile-columns=0','--tile-rows=0','--superres-mode=0','--timing-info=0','--ivf']
 out=r/('q'+str(qp)+'.ivf');command=[str(a.aomenc),*flags,'-o',str(out),str(r/'input.i420')];print(' '.join(command));subprocess.run(command,check=True);(r/name).write_bytes(frame(out.read_bytes()))
n=w*h;(r/'frame.bin').write_bytes(source[:n]+bytes(x for pair in zip(source[n:n+n//4],source[n+n//4:])for x in pair))
