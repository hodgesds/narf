#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sync_smoke_x86_64.c -o sync_smoke_x86_64
