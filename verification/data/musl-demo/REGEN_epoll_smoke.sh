#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large epoll_smoke_x86_64.c -o epoll_smoke_x86_64
