#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large dmabuf_sync_smoke_x86_64.c -o dmabuf_sync_smoke_x86_64
