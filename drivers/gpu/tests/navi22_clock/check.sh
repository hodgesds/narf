#!/usr/bin/env bash
# Explicit Linux reference gate; also discovered by gpu-reference.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
linux=${1:?pass the Linux source tree}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cc -std=c11 -Wall -Wextra -Werror -D'__counted_by(x)=' \
    -I"$linux/drivers/gpu/drm/amd/include" \
    -I"$linux/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn30" \
    -I"$linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if" \
    "$here/../navi22_clock.c" -o "$work/navi22-clock"
"$work/navi22-clock"
echo 'Navi22 DAL/PPSMC, DENTIST/DPP DTO and ATOM clock wire contracts match Linux headers'
