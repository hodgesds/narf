#!/bin/bash
# The NARF acceptance image is testing a native Plasma Wayland session.  A
# failed Xwayland startup can still leave a listening X11 socket behind;
# kcminit's phase-zero style module then blocks forever in xcb_connect().
# Keep that optional compatibility path from gating the native shell.
unset DISPLAY
# kcminit selects its startup/phase-zero mode from argv[0]. Preserve the
# package entry-point name even though the real symlink has been moved aside.
exec -a kcminit_startup /usr/bin/kcminit_startup.narf-real "$@"
