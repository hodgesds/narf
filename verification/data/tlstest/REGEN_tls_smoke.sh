#!/bin/sh
musl-gcc -shared -fPIC -O2 -Wl,-soname,libtls.so libtls.c -o libtls.so
musl-gcc -O2 -fPIE -pie -mcmodel=large tls_smoke.c -L. -ltls -Wl,-rpath,/lib -o tls_smoke_x86_64
