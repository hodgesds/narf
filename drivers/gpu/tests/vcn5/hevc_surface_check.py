#!/usr/bin/env python3
"""Check actual primary GFX12 surface layouts against both HEVC proof messages.
Usage: hevc_surface_check.py /path/to/mesa-26.2.4 --gpu /path/to/drivers/gpu
Compiles unchanged Addrlib with two workers; never accesses a GPU device.
"""
import argparse
import ast
import concurrent.futures
import io
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('mesa',type=Path)
p.add_argument('--gpu',type=Path,default=Path(__file__).resolve().parents[2])
p.add_argument('--build-dir',type=Path)
p.add_argument('--emit-json',type=Path)
a=p.parse_args()
mesa=a.mesa.resolve();gpu=a.gpu.resolve();addr=mesa/'src/amd/addrlib'

# Run unchanged generator functions on actual selected YAML records, without
# requiring a full Mesa build or PyYAML. No width/subsample mapping is restated.
yaml=(mesa/'src/util/format/u_format.yaml').read_text()
records={m[1]:m[0] for m in re.finditer(r'^- name: (\w+)\n(?:(?!^- name:)[\s\S])*',yaml,re.M)}
formats=[]
for name in ['Y8_U8V8_420_UNORM','X6Y10_X6U10X6V10_420_UNORM']:
    record=records[name]
    fmt=SimpleNamespace(name='PIPE_FORMAT_'+name,layout=re.search(r'^  layout: (\w+)',record,re.M)[1],colorspace=re.search(r'^  colorspace: (\w+)',record,re.M)[1],short_name=lambda n=name:n.lower())
    formats.append(fmt)
source=(mesa/'src/util/format/u_format_table.py').read_text();tree=ast.parse(source)
names={'chroma_horizontal_subsample_factor','chroma_vertical_subsample_factor','write_get_plane_width_height','write_get_plane_format'}
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='CHROMA_SUBSAMP' for t in n.targets)]
namespace={'sys':SimpleNamespace(stdout3=io.StringIO())};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(mesa/'src/util/format/u_format_table.py'),'exec'),namespace)
namespace['write_get_plane_format'](formats);namespace['write_get_plane_width_height'](formats)
helpers=namespace['sys'].stdout3.getvalue()
texture=(mesa/'src/gallium/drivers/radeonsi/si_texture.c').read_text()
m=re.search(r'static enum pipe_format\nsi_get_plane_format\(',texture);start=m.start();opening=texture.index('{',m.end());depth=1;end=opening+1
while depth:depth+=(texture[end]=='{')-(texture[end]=='}');end+=1
helpers+='\n'+texture[start:end]
enums=set(re.findall(r'PIPE_FORMAT_[A-Z0-9_]+',helpers))
# Physical channel size is derived from each actual primary plane format record.
bitfunc='static unsigned bits_per_element(pipe_format format) {switch(format){\n'
for name in ['R8_UNORM','RG88_UNORM','R16_UNORM','R16G16_UNORM']:
    record=records.get(name)
    if record is None:
        matches=[r for r in records.values()if re.search(r'  little_endian:\n    alias: '+name+r'\b',r)]
        assert len(matches)==1,(name,len(matches));record=matches[0]
    channels=re.search(r'^  channels: \[([^]]*)\]',record,re.M)[1]
    bits=sum(int(n)for n in re.findall(r'\d+',channels));assert bits>0
    bitfunc+='case PIPE_FORMAT_'+name+':return '+str(bits)+';\n';enums.add('PIPE_FORMAT_'+name)
bitfunc+='default:abort();}}\n'
copyright_notice=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='CopyRight'for t in n.targets))
header=copyright_notice+'#include <initializer_list>\n#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))\nenum pipe_format {'+','.join(sorted(enums))+'};\n'+helpers+'\n'+bitfunc

with tempfile.TemporaryDirectory(prefix='narf-hevc-surfaces-')as temporary:
    build=a.build_dir or Path(temporary);build.mkdir(parents=True,exist_ok=True)
    (build/'plane_helpers.h').write_text(header)
    includes=[addr/x for x in ['inc','src','src/core','src/chip/gfx9','src/chip/r800','src/chip/gfx10','src/chip/gfx11','src/chip/gfx12']]
    flags=['-std=c++17','-O1','-DNDEBUG','-DADDR_FASTCALL=','-DLITTLEENDIAN_CPU','-DDEBUG=0','-DADDR_ALLOW_SIMD=0']+['-I'+str(x)for x in includes]
    sources=[addr/x for x in re.findall(r"'([^']+\.cpp)'",(addr/'meson.build').read_text())]
    digest=hashlib.sha256(' '.join(flags).encode())
    for dependency in sorted(addr.rglob('*')):
        if dependency.suffix in {'.h','.cpp'}:
            digest.update(dependency.relative_to(addr).as_posix().encode());digest.update(dependency.read_bytes())
    objects_dir=build/('addrlib-'+digest.hexdigest()[:16]);objects_dir.mkdir(exist_ok=True)
    def compile_one(src):
        obj=objects_dir/(src.relative_to(addr).as_posix().replace('/','_')+'.o')
        if not obj.exists()or src.stat().st_mtime_ns>obj.stat().st_mtime_ns:
            subprocess.run(['c++',*flags,'-c',str(src),'-o',str(obj)],check=True,capture_output=True)
        return obj
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2)as workers:objects=list(workers.map(compile_one,sources))
        harness=Path(__file__).with_name('hevc_surface_reference.cpp')
        subprocess.run(['c++',*flags,'-UNDEBUG','-Wall','-Wextra','-Werror','-I'+str(build),str(harness),*[str(o)for o in objects],'-o',str(build/'surfaces')],check=True)
    except subprocess.CalledProcessError as error:
        if error.stderr:sys.stderr.write(error.stderr.decode()if isinstance(error.stderr,bytes)else error.stderr)
        raise
    rows=[tuple(map(int,line.split()))for line in subprocess.check_output([str(build/'surfaces')],text=True).splitlines()]
    # Actual Rust message bytes, not another manually entered pitch descriptor.
    rust='''#[derive(Debug)]enum Error{Invalid}
#[allow(dead_code)]#[path="WORDS8"]mod a;
#[allow(dead_code)]#[path="WORDS10"]mod b;
fn main(){for msg in [a::decode_message(),b::decode_message()]{for byte in msg{print!("{byte:02x}");}println!();}}'''.replace('WORDS8',str(gpu/'src/amdgpu_vcn_navi48_hevc_words.rs')).replace('WORDS10',str(gpu/'src/amdgpu_vcn_navi48_hevc10_words.rs'))
    (build/'messages.rs').write_text(rust)
    subprocess.run(['rustc','--edition=2021',str(build/'messages.rs'),'-o',str(build/'messages')],check=True)
    messages=[bytes.fromhex(line)for line in subprocess.check_output([str(build/'messages')],text=True).splitlines()]
    for row in rows:
        rev,depth,policy,yp,uvp,ys,uvs,yt,uvt,ya,uva,offset,total,yh,uvh=row
        msg=messages[depth==10];decode=msg[56:244]
        word=lambda i:int.from_bytes(decode[i*4:i*4+4],'little')
        if policy==0:
            assert(word(25),word(26))==(yp,uvp),(rev,depth,'sample pitches',(word(25),word(26)),(yp,uvp))
            assert word(36)==offset,(rev,depth,'UV offset',word(36),offset)
            assert word(6)==total,(rev,depth,'target size',word(6),total)
            assert ys==yt and uvs==uvt and offset>=ys
        else:
            # Mesa's interop policy can enlarge8-bit rows; it must not be
            # silently substituted for the explicit compact proof allocation.
            assert yp*(2 if depth==10 else 1)>=256 and uvp*(2 if depth==10 else 1)*2>=256
        print('gfx12 revision',hex(rev),'depth',depth,'interop',policy,'sample pitches',yp,uvp,'UV offset',offset,'target',total)
if a.emit_json:a.emit_json.write_text(json.dumps([dict(zip(['revision','depth','policy','y_pitch','uv_pitch','y_slice_size','uv_slice_size','y_size','uv_size','y_align','uv_align','uv_offset','target_size','y_height','uv_height'],row))for row in rows]))
print('Both HEVC target planes match actual GFX12 Addrlib surfaces and byte addresses.')
