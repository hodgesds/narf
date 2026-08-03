#!/bin/bash
# Diagnostic wrapper for the Fedora Plasma acceptance image.  Xwayland feeds
# a generated keymap to xkbcomp on stdin; save those exact bytes before the
# compiler sees them so a producer defect can be distinguished from pipe or
# exec transport corruption.
set -u

capture_dir=${XDG_RUNTIME_DIR:-/tmp}
capture_path="$capture_dir/narf-xkbcomp-$$.stdin"

if ! /usr/bin/cat > "$capture_path"; then
  echo "XKBCOMP-CAPTURE: failed to save stdin at $capture_path" >&2
  exit 125
fi

bytes=$(/usr/bin/wc -c < "$capture_path")
echo "XKBCOMP-CAPTURE pid=$$ bytes=$bytes path=$capture_path args=$*" >&2
exec /usr/bin/xkbcomp.narf-real "$@" < "$capture_path"
