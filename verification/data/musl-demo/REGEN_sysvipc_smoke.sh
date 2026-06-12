#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sysvipc_smoke_x86_64.c -o sysvipc_smoke_x86_64
