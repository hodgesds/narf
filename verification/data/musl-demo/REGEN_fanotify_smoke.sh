#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fanotify_smoke_x86_64.c -o fanotify_smoke_x86_64
