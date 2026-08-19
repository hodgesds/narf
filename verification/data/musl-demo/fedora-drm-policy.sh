#!/bin/sh
# Device ownership for the synthetic DRM nodes used by the Fedora desktop.
set -eu

# udev coldplug cannot currently create nested aliases beneath devfs even
# though it can create the DRM nodes themselves.  These standard devnum
# aliases are what logind and libdrm resolve before opening the card; install
# them deterministically before the Plasma service starts.
/usr/bin/mkdir -p /dev/char
/usr/bin/ln -sfn ../dri/card0 /dev/char/226:0
/usr/bin/ln -sfn ../dri/renderD128 /dev/char/226:128

/usr/bin/chown 0:39 /dev/dri/card0
/usr/bin/chmod 0660 /dev/dri/card0
/usr/bin/chmod 0666 /dev/dri/renderD128
