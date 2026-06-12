#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large vio_smoke_x86_64.c -o vio_smoke_x86_64
