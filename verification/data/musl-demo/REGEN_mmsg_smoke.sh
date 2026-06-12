#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mmsg_smoke_x86_64.c -o mmsg_smoke_x86_64
