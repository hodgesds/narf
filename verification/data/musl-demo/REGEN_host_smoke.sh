#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large host_smoke_x86_64.c -o host_smoke_x86_64
