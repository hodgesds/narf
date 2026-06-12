#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large inotify_smoke_x86_64.c -o inotify_smoke_x86_64
