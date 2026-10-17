// GC12 clear-state extents from Linux clearstate_gfx12.h, compressed because
// all 62 register defaults are zero. RLC consumes clusters, not PM4 packets.
//
// Copyright 2023 Advanced Micro Devices, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
pub const DWORDS: usize = 75;
pub const fn image() -> [u32; DWORDS] {
    let extents = [
        (0xa03e, 34),
        (0xa0cc, 2),
        (0xa0d8, 1),
        (0xa0db, 6),
        (0xa2e5, 11),
        (0xa3c0, 8),
    ];
    let mut words = [0; DWORDS];
    words[0] = 6;
    let mut i = 0;
    let mut at = 1;
    while i < extents.len() {
        words[at] = extents[i].1;
        words[at + 1] = extents[i].0;
        at += 2 + extents[i].1 as usize;
        i += 1;
    }
    words
}
