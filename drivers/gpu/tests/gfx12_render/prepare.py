#!/usr/bin/env python3
"""Extract hash-pinned sources and expose only linkage to unchanged constructors."""
import hashlib
from pathlib import Path
import sys
import tarfile

here = Path(__file__).resolve().parent
work, mesa_archive, drm_archive = map(Path, sys.argv[1:])
pins = [(mesa_archive, 'bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9'),
        (drm_archive, 'ac5e74d157830eb8bee44c6a6bf3ad49774ef0dd2a72bdad74a8f20308b52a95')]
for archive, expected in pins:
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'{archive}: source SHA256 mismatch: {actual}')
    with tarfile.open(archive) as source:
        source.extractall(work / 'primary', filter='data')
mesa = work / 'primary/mesa-26.2.4'
assert (mesa / 'VERSION').read_text().strip() == '26.2.4'

def edit(name, old, new):
    path = mesa / name
    text = path.read_text()
    assert text.count(old) == 1, f'unknown pinned constructor shape: {name}: {old}'
    path.write_text(text.replace(old, new))

edit('src/amd/vulkan/meson.build', 'libvulkan_radeon = shared_library(',
     "libradv_files += files('tests/narf_render_fixture.c')\n\nlibvulkan_radeon = shared_library(")
edit('src/vulkan/vulkan.sym', 'global:\n', 'global:\n\t\tnarf_render_fixture;\n')
# Linkage/prototypes only; do not replace any shader, layout, register or
# PM4 constructor body with a local model.
path = mesa / 'src/amd/vulkan/meta/radv_meta_clear.c'
text = path.read_text().replace('static VkResult\nget_color_pipeline(', 'VkResult\nnarf_get_color_pipeline(')
text = text.replace('get_color_pipeline(device,', 'narf_get_color_pipeline(device,')
assert text.count('\nnarf_get_color_pipeline(') == 1
at = text.index('\nstatic ')
path.write_text(text[:at] + '\n#include "tests/narf_render_fixture.h"\n' + text[at:])
path = mesa / 'src/amd/vulkan/radv_queue.c'
text = path.read_text()
for name in ['fill_shader_rings', 'emit_ge_rings', 'emit_graphics_shader_pointers']:
    old = f'static void\nradv_{name}('
    assert text.count(old) == 1
    text = text.replace(old, f'void\nnarf_{name}(').replace(f'radv_{name}(', f'narf_{name}(')
at = text.index('\nstatic ')
path.write_text(text[:at] + '\n#include "tests/narf_render_fixture.h"\n' + text[at:])
for suffix in ['c', 'h']:
    (mesa / f'src/amd/vulkan/tests/narf_render_fixture.{suffix}').write_bytes((here / f'fixture.{suffix}').read_bytes())
(work / 'SOURCE.sha256').write_text(''.join(f'{h}  {p.name}\n' for p,h in pins))
