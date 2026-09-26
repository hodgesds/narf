#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large profloop_smoke_x86_64.c -o profloop_smoke_x86_64
