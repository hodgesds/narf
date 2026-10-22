#!/usr/bin/env python3
"""Regenerate the original Main8 fixture using the pinned tools in README.md."""
import argparse
import hashlib
import struct
from pathlib import Path
import subprocess
import tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--x265',type=Path,required=True)
p.add_argument('--ffmpeg',type=Path,required=True)
p.add_argument('--main10',action='store_true')
a=p.parse_args()
w=h=128
source=bytes(32 if x<64 and y<64 else 80 if y<64 else 144 if x<64 else 208 for y in range(h) for x in range(w))+bytes([64])*(w*h//4)+bytes([192])*(w*h//4)
if a.main10:
    values=[129 if x<64 and y<64 else 321 if y<64 else 577 if x<64 else 833 for y in range(h) for x in range(w)]+[259]*(w*h//4)+[771]*(w*h//4)
    source=struct.pack('<'+'H'*len(values),*values)
with tempfile.TemporaryDirectory(prefix='narf-hevc-regenerate-') as temp:
    d=Path(temp)
    subprocess.run([str(a.x265),'--input','-','--input-res','128x128','--fps','1','--input-depth','10' if a.main10 else '8','--input-csp','i420','--profile','main10' if a.main10 else 'main','--frame-threads','1','--pools','none','--no-wpp','--keyint','2','--min-keyint','2','--bframes','0','--ref','1','--no-sao','--no-deblock','--no-strong-intra-smoothing','--no-temporal-mvp','--no-weightp','--no-weightb','--no-signhide','--scaling-list','off','--no-info','--no-aud','--no-cutree','--aq-mode','0','--qp','0' if a.main10 else '22','--output',str(d/'proof.hevc')],input=source,check=True,capture_output=True)
    encoded=(d/'proof.hevc').read_bytes()
    assert hashlib.sha256(encoded).hexdigest()==('11f4e8621dd28676980f61687c94a746cb68ce586e7bf9075a072bcbf729b85f' if a.main10 else '26a5c91dacb9c140fe7dc624a3f57d9005657bc2b51d7a12ed34269b73458256')
    subprocess.run([str(a.ffmpeg),'-v','error','-i',str(d/'proof.hevc'),'-frames:v','1','-pix_fmt','yuv420p10le' if a.main10 else 'yuv420p','-f','rawvideo',str(d/'decoded.i420')],check=True)
    raw=(d/'decoded.i420').read_bytes();assert raw==source
    n=w*h
    if a.main10:
        samples=struct.unpack('<'+'H'*(len(raw)//2),raw)
        out=samples[:n]+tuple(value for pair in zip(samples[n:n+n//4],samples[n+n//4:])for value in pair)
        decoded=struct.pack('<'+'H'*len(out),*(v<<6 for v in out))
    else:
        decoded=raw[:n]+bytes(value for pair in zip(raw[n:n+n//4],raw[n+n//4:]) for value in pair)
    assert hashlib.sha256(decoded).hexdigest()==('7c8a710cc653140480b728b7769d34d2f77c46cc30766530e9fc7b6742646c01' if a.main10 else 'af4b8817ee41af9585b6687e9969414a065e7f1a673e9204784daaab0820618b')
print(('Pinned Main10' if a.main10 else 'Pinned Main8')+' stream regenerated; independent decode matches every original pixel.')
