#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large virgl3d_smoke_x86_64.c -o virgl3d_smoke_x86_64
