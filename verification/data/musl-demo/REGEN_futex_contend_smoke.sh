#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large futex_contend_smoke_x86_64.c -o futex_contend_smoke_x86_64
