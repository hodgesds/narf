#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large waitid_smoke_x86_64.c -o waitid_smoke_x86_64
