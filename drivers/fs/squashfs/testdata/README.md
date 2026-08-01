# SquashFS conformance fixtures

`linux-gzip.sqfs` is a deterministic SquashFS 4.0 image produced by
squashfs-tools 4.6.1. It contains a nested directory, regular data, a symlink,
a FIFO, a sparse multi-block file, and a fragment tail. The locally available
squashfs-tools binary was built without xattr or LZ4 authoring. Those formats
are implemented with bounded decoders, but generated-image coverage remains a
recorded audit gap.

Regenerate with `sh REGEN_fixture.sh`. The test suite mounts the image through
`RamBlockDevice`; corrupt-input cases clone and mutate the bytes in memory so
malformed fixtures are not stored separately.
