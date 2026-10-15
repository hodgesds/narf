#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large wlproxy_sockpair_smoke_x86_64.c -o wlproxy_sockpair_smoke_x86_64
