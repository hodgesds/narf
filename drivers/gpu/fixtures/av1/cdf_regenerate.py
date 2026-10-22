#!/usr/bin/env python3
"""Execute unchanged Mesa VCN5 decoder CDF initialization into an explicit file."""
from pathlib import Path
import argparse,hashlib,subprocess,sys,tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tests/vcn5'))
from decode_primary import primary_pieces
p=argparse.ArgumentParser(description=__doc__);p.add_argument('mesa',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='narf-av1-cdf-')as temp:
    d=Path(temp);(d/'primary.h').write_text('\n'.join(primary_pieces(a.mesa,'av1')))
    (d/'dump.c').write_text('#include "primary.h"\nint main(int argc,char**argv){if(argc!=2)return 1;unsigned frame=ac_vcn_dec_frame_ctx_size_av1(RDECODE_AV1_VER_2);uint8_t*data=calloc(4,frame);ac_vcn_av1_init_probs(RDECODE_AV1_VER_2,data);FILE*f=fopen(argv[1],"wb");if(!f)return 2;if(fwrite(data,frame,4,f)!=4)return 3;return fclose(f);}')
    subprocess.run(['cc','-std=c11','-Wno-unused-function','-I'+str(d),str(d/'dump.c'),'-lm','-o',str(d/'dump')],check=True)
    subprocess.run([str(d/'dump'),str(a.output.resolve())],check=True)
    data=a.output.read_bytes();assert len(data)==81920
    assert hashlib.sha256(data).hexdigest()=='3e7d9954ccdda4207222de61f3661396e0c43d39fc59bdba0f79da5443ed5890'
print('Actual pinned Mesa decoder CDF initialization matches81920-byte reference.')
