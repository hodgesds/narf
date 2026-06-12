#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large creds_smoke_x86_64.c -o creds_smoke_x86_64
