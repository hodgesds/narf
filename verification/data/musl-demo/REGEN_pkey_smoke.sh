#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pkey_smoke_x86_64.c -o pkey_smoke_x86_64
