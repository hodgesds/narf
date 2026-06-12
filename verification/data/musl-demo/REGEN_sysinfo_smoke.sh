#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sysinfo_smoke_x86_64.c -o sysinfo_smoke_x86_64
