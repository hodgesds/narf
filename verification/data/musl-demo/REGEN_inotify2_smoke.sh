#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large inotify2_smoke_x86_64.c -o inotify2_smoke_x86_64
