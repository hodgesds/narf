#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sockpairfork_smoke_x86_64.c -o sockpairfork_smoke_x86_64
