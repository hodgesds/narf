#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large keyring_smoke_x86_64.c -o keyring_smoke_x86_64
