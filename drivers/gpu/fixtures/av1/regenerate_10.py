#!/usr/bin/env python3
"""Regenerate the original fixed 10-bit AV1 keyframe using pinned primary tools."""
from pathlib import Path
import argparse,hashlib,struct,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--aomenc',type=Path,required=True);p.add_argument('--ffmpeg',type=Path,required=True);a=p.parse_args()
w,h=256,128;n=w*h
samples=[129 if x<w//2 and y<h//2 else 321 if y<h//2 else 577 if x<w//2 else 833 for y in range(h)for x in range(w)]+[259]*(n//4)+[771]*(n//4)
source=b''.join(x.to_bytes(2,'little')for x in samples)
flags=['--codec=av1','--profile=0','--bit-depth=10','--input-bit-depth=10','--width=256','--height=128','--fps=1/1','--limit=1','--passes=1','--threads=1','--cpu-used=0','--lag-in-frames=0','--end-usage=q','--cq-level=0','--lossless=1','--kf-max-dist=0','--kf-min-dist=0','--sb-size=64','--enable-order-hint=0','--enable-cdef=0','--enable-restoration=0','--enable-filter-intra=0','--enable-intra-edge-filter=0','--enable-dual-filter=0','--enable-ref-frame-mvs=0','--enable-global-motion=0','--enable-warped-motion=0','--enable-interintra-comp=0','--enable-masked-comp=0','--enable-obmc=0','--enable-palette=0','--enable-intrabc=0','--enable-qm=0','--deltaq-mode=0','--delta-lf-mode=0','--cdf-update-mode=0','--tile-columns=0','--tile-rows=0','--superres-mode=0','--timing-info=0','--ivf']
with tempfile.TemporaryDirectory(prefix='narf-av1-10-regenerate-')as temp:
    d=Path(temp);(d/'input.i420').write_bytes(source)
    subprocess.run([str(a.aomenc),*flags,'-o',str(d/'proof.ivf'),str(d/'input.i420')],check=True,capture_output=True)
    ivf=(d/'proof.ivf').read_bytes();assert ivf[:4]==b'DKIF' and ivf[8:12]==b'AV01'
    size=struct.unpack_from('<I',ivf,32)[0];stream=ivf[44:];assert len(stream)==size==196
    assert hashlib.sha256(stream).hexdigest()=='f4e46774a0f69d2a624b10ed6896dcdbee53feee1a1a4676364b6079143e2a00'
    subprocess.run([str(a.ffmpeg),'-v','error','-i',str(d/'proof.ivf'),'-frames:v','1','-pix_fmt','yuv420p10le','-f','rawvideo',str(d/'decoded.i420')],check=True)
    assert(d/'decoded.i420').read_bytes()==source
print('Pinned AV1 keyframe regenerated; independent decode matches every original sample.')
