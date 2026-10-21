#!/usr/bin/env bash
# The vector inputs check.sh answers with Linux (see harness.c's grammar).
set -euo pipefail
# Both GFX12 dies (GC 12.0.0 Navi44, 12.0.1 Navi48), TCC counts powers of
# two or not (the 1- and 2-TCC ones align to 0 and take the ordinary path),
# and another GC minor (no alignment); sizes from a page to 64 MiB, free
# space starting at assorted offsets.
for minor in 0 1 2; do
	for tccs in 1 2 3 4 5 6 8 10 12 16 20 24 32; do
		for size in 4096 65536 135168 1048576 2097152 8294400 8298496 33177600 67108864; do
			for base in 0 4096 2097152 3145728 100663296; do
				echo "D $minor $tccs $size $base"
			done
		done
	done
done
