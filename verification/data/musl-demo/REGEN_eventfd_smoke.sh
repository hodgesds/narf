#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large eventfd_smoke_x86_64.c -o eventfd_smoke_x86_64
