#!/usr/bin/env python3
"""Regenerate the original lossless Profile0 keyframe with pinned tools."""
from pathlib import Path
import argparse
import hashlib
import struct
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--vpxenc',type=Path,required=True)
p.add_argument('--ffmpeg',type=Path,required=True)
p.add_argument('--profile2',action='store_true')
a=p.parse_args()
n=128*128
source=bytes(32 if x<64 and y<64 else 80 if y<64 else 144 if x<64 else 208 for y in range(128)for x in range(128))+bytes([64])*(n//4)+bytes([192])*(n//4)
if a.profile2:
    samples=[129 if x<64 and y<64 else 321 if y<64 else 577 if x<64 else 833 for y in range(128)for x in range(128)]+[259]*(n//4)+[771]*(n//4)
    source=struct.pack('<'+'H'*len(samples),*samples)
with tempfile.TemporaryDirectory(prefix='narf-vp9-regenerate-')as temp:
    d=Path(temp);(d/'input.i420').write_bytes(source)
    subprocess.run([str(a.vpxenc),'--codec=vp9','--profile=2' if a.profile2 else '--profile=0',*(['--bit-depth=10','--input-bit-depth=10']if a.profile2 else []),'--width=128','--height=128','--fps=1/1','--limit=1','--passes=1','--threads=1','--tile-columns=0','--tile-rows=0','--frame-parallel=1','--error-resilient=1','--lossless=1','--ivf','--output='+str(d/'proof.ivf'),str(d/'input.i420')],check=True,capture_output=True)
    ivf=(d/'proof.ivf').read_bytes();assert ivf[:4]==b'DKIF' and ivf[8:12]==b'VP90'
    size=struct.unpack_from('<I',ivf,32)[0];payload=ivf[44:];assert len(payload)==size==(69 if a.profile2 else 64)
    assert hashlib.sha256(payload).hexdigest()==('43fa8123ae12129fa97147b98d948fa4c6c49dfd804f5430ad2d2077c7ce4576' if a.profile2 else '8720e79f246912d0d8001e0517b68f81be764b9d0102334ddf500f613ee6e453')
    subprocess.run([str(a.ffmpeg),'-v','error','-i',str(d/'proof.ivf'),'-frames:v','1','-pix_fmt','yuv420p10le' if a.profile2 else 'yuv420p','-f','rawvideo',str(d/'decoded.i420')],check=True)
    assert(d/'decoded.i420').read_bytes()==source
print(('Pinned VP9 Profile2' if a.profile2 else 'Pinned VP9 Profile0')+' keyframe regenerated; independent decode matches every source sample.')
