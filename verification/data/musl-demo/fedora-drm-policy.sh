#!/bin/sh
# Apply and expose the synthetic DRM-node policy used by the Fedora Plasma
# acceptance image. Numeric IDs avoid making early graphical startup depend on
# NSS; Fedora's `video` group is gid 39 in this image.
set -x
/usr/bin/ls -ln /dev/dri
/usr/bin/chown 0:39 /dev/dri/card0
/usr/bin/chmod 0660 /dev/dri/card0
/usr/bin/chmod 0666 /dev/dri/renderD128
/usr/bin/ls -ln /dev/dri
