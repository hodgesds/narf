#!/usr/bin/env python3
"""Inputs for check.sh: DCN4 streams (their pipes as DC's scaler data
describes them) and cursors over them. See harness.c for the format."""

ONE = 1 << 19 << 5  # SPL's h_scale_ratio register for 1:1


def ratio(num, den):
    """SPL's U3.19 ratio register (<< 5) for num/den, truncated."""
    return ((num << 19) // den) << 5


def pipe(seg, layer, recout, viewport, r, src, slice_w):
    return (seg, layer) + tuple(recout) + tuple(viewport) + (r, src[0], src[1], slice_w)


def full(seg, layer, w, h, slice_w, vx=0, src=None):
    return pipe(seg, layer, (0, 0, w, h), (vx, 0, w, h), ONE, src or (w, h), slice_w)


CONFIGS = []


def config(name, clocks, pipes, positions):
    CONFIGS.append((name, clocks, pipes, positions))


HD = (100_000, 148_500)
UHD = (50_000, 594_000)
EIGHT_K = (50_000, 1_188_000)
EDGE = [(-100, -100), (-64, 0), (0, -64), (-63, 5), (-10, -5), (0, 0), (5, 7),
        (1859, 1000), (1880, 1040), (1919, 1079), (1920, 1080), (1856, 1016)]

# One full-frame pipe.
config("single", HD, [full(0, 0, 1920, 1080, 1920)],
       EDGE + [(100, 50), (960, 540), (1000, 1079)])
# An unscaled overlay above the primary.
OV = (100, 100, 640, 360)
config("overlay", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, OV, (0, 0, 640, 360), ONE, (640, 360), 1920),
], EDGE + [(90, 90), (99, 99), (100, 100), (420, 280), (700, 400), (739, 459),
           (740, 460), (36, 36), (37, 37), (60, 300)])
# A 2:1 downscaled overlay, a 1:4 upscaled one.
config("overlay-down", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (200, 150, 640, 360), (0, 0, 1280, 720), ratio(2, 1), (1280, 720), 1920),
], EDGE + [(190, 140), (200, 150), (500, 300), (839, 509), (840, 510), (150, 100)])
config("overlay-up", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (0, 0, 1280, 720), (0, 0, 320, 180), ratio(1, 4), (320, 180), 1920),
], EDGE + [(100, 100), (640, 360), (1279, 719), (1280, 720), (1250, 700)])
# A cropped overlay (viewport inside its source), partly off the stream.
config("overlay-cropped", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (1600, 900, 320, 180), (0, 0, 320, 180), ONE, (640, 360), 1920),
], EDGE + [(1590, 890), (1600, 900), (1700, 950), (1918, 1078)])
# A full-screen overlay hides the primary's cursor; so does a primary over
# its underlay.
config("covering", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (0, 0, 1920, 1080), (0, 0, 1920, 1080), ONE, (1920, 1080), 1920),
], EDGE + [(500, 500)])
config("underlay", HD, [
    pipe(0, 0, (300, 200, 800, 600), (0, 0, 800, 600), ONE, (800, 600), 1920),
    full(0, 1, 1920, 1080, 1920),
], EDGE + [(290, 190), (300, 200), (700, 500)])
# Two overlays, the upper one overlapping the lower.
config("two-overlays", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (100, 100, 800, 600), (0, 0, 800, 600), ONE, (800, 600), 1920),
    pipe(0, 2, (500, 400, 400, 300), (0, 0, 400, 300), ONE, (400, 300), 1920),
], EDGE + [(100, 100), (480, 380), (500, 400), (870, 680), (899, 699), (900, 700)])
# ODM 2:1 at 4K, 3:1 / 4:1 at 8K; a 4:2:0 4:1 stream's later slices one
# pixel wider to the left.
config("odm2", UHD, [
    full(0, 0, 1920, 2160, 1920, 0, (3840, 2160)),
    full(1, 0, 1920, 2160, 1920, 1920, (3840, 2160)),
], [(-10, 0), (0, 0), (1856, 100), (1880, 100), (1900, 100), (1919, 100),
    (1920, 100), (1921, 100), (1950, 100), (3800, 2100), (3839, 2159), (3840, 0)])
config("odm3", EIGHT_K, [
    full(0, 0, 2560, 4320, 2560, 0, (7680, 4320)),
    full(1, 0, 2560, 4320, 2560, 2560, (7680, 4320)),
    full(2, 0, 2560, 4320, 2560, 5120, (7680, 4320)),
], [(2500, 10), (2530, 10), (2560, 10), (5100, 10), (5119, 10), (5120, 10), (7679, 4319)])
config("odm4-420", EIGHT_K, [
    full(0, 0, 1920, 4320, 1920, 0, (7680, 4320)),
    pipe(1, 0, (0, 0, 1921, 4320), (1919, 0, 1921, 4320), ONE, (7680, 4320), 1921),
    pipe(2, 0, (0, 0, 1921, 4320), (3839, 0, 1921, 4320), ONE, (7680, 4320), 1921),
    pipe(3, 0, (0, 0, 1921, 4320), (5759, 0, 1921, 4320), ONE, (7680, 4320), 1921),
], [(1900, 5), (1919, 5), (1920, 5), (1921, 5), (3800, 5), (3841, 5), (3842, 5),
    (5760, 5), (5763, 5), (7679, 4319)])
# ODM 2:1 with an overlay straddling the slices.
config("odm2-overlay", UHD, [
    full(0, 0, 1920, 2160, 1920, 0, (3840, 2160)),
    pipe(0, 1, (1800, 500, 120, 300), (0, 0, 120, 300), ONE, (400, 300), 1920),
    full(1, 0, 1920, 2160, 1920, 1920, (3840, 2160)),
    pipe(1, 1, (0, 500, 280, 300), (120, 0, 280, 300), ONE, (400, 300), 1920),
], [(1790, 490), (1800, 500), (1890, 600), (1900, 600), (1919, 600), (1920, 600),
    (2150, 790), (2199, 799), (2200, 800), (1760, 450)])
# MPC combine: a primary split into two slices (each lower slice below the
# one before), unscaled and 2:1 down; an overlay above a split primary; an
# overlay split over an unsplit primary.
config("mpc2", HD, [
    pipe(0, 0, (960, 0, 960, 1080), (960, 0, 960, 1080), ONE, (1920, 1080), 1920),
    pipe(0, 0, (0, 0, 960, 1080), (0, 0, 960, 1080), ONE, (1920, 1080), 1920),
], EDGE + [(900, 10), (930, 10), (959, 10), (960, 10), (961, 10)])
config("mpc2-down", UHD, [
    pipe(0, 0, (960, 0, 960, 1080), (1920, 0, 1920, 2160), ratio(2, 1), (3840, 2160), 1920),
    pipe(0, 0, (0, 0, 960, 1080), (0, 0, 1920, 2160), ratio(2, 1), (3840, 2160), 1920),
], [(0, 0), (500, 500), (930, 10), (959, 10), (960, 10), (1500, 1000), (1919, 1079)])
config("mpc2-overlay", HD, [
    pipe(0, 0, (960, 0, 960, 1080), (960, 0, 960, 1080), ONE, (1920, 1080), 1920),
    pipe(0, 0, (0, 0, 960, 1080), (0, 0, 960, 1080), ONE, (1920, 1080), 1920),
    pipe(0, 1, (800, 400, 400, 300), (0, 0, 400, 300), ONE, (400, 300), 1920),
], [(790, 390), (800, 400), (950, 500), (960, 500), (1199, 699), (1200, 700)])
config("overlay-mpc2", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (960, 0, 960, 1080), (960, 0, 960, 1080), ONE, (1920, 1080), 1920),
    pipe(0, 1, (0, 0, 960, 1080), (0, 0, 960, 1080), ONE, (1920, 1080), 1920),
], [(0, 0), (950, 500), (960, 500), (1919, 1079)])
config("overlay-mpc2-half", HD, [
    full(0, 0, 1920, 1080, 1920),
    pipe(0, 1, (480, 270, 480, 540), (480, 0, 480, 540), ONE, (960, 540), 1920),
    pipe(0, 1, (0, 270, 480, 540), (0, 0, 480, 540), ONE, (960, 540), 1920),
], [(0, 270), (470, 300), (480, 300), (959, 809), (960, 810)])

SIZES = [(64, 64), (32, 32), (64, 48), (1, 1), (20, 60)]

print("# Generated by gen_inputs.py: DCN4 streams and cursors; see harness.c.")
for name, (ref, pix), pipes, positions in CONFIGS:
    print(f"# {name}")
    body = " ".join(" ".join(str(v) for v in p) for p in pipes)
    for (x, y) in positions:
        for (w, h) in SIZES:
            print(f"{x} {y} {w} {h} {ref} {pix} {len(pipes)} {body}")
