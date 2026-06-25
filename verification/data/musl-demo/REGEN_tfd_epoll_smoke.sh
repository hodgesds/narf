#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large tfd_epoll_smoke_x86_64.c -o tfd_epoll_smoke_x86_64
