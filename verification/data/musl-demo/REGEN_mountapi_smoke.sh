#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mountapi_smoke_x86_64.c -o mountapi_smoke_x86_64
