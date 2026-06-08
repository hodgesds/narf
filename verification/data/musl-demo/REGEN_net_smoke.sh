#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large net_smoke_x86_64.c -o net_smoke_x86_64
