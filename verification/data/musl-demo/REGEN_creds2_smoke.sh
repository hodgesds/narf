#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large creds2_smoke_x86_64.c -o creds2_smoke_x86_64
