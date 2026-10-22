#!/usr/bin/env bash
# Run Linux's DAL wait/send functions verbatim against mailbox fault models.
# NARF intentionally rejects an unknown inherited busy mailbox, but follows
# Linux after a timeout from a completed ignored-result helper it sent itself.
set -euo pipefail
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
linux=${1:-/usr/src/linux}
source=$linux/drivers/gpu/drm/amd/display/dc/clk_mgr/dcn401/dcn401_clk_mgr_smu_msg.c
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
{
    cat "$here/shim.h"
    for fn in dcn401_smu_wait_for_response dcn401_smu_send_msg_with_param; do
        awk -v n="$fn" '
            !f && $0 ~ "^static .* " n "\\(" { f = 1 }
            f { print }
            f && /^}/ { exit }' "$source"
    done
    cat "$here/harness.c"
} > "$work/mailbox.c"
cc -std=gnu11 -O1 -Wall -Wextra -Werror -Wno-unused-parameter \
    "$work/mailbox.c" -o "$work/mailbox"
"$work/mailbox"
