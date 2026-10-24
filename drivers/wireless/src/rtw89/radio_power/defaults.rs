// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Original B static power SHA256 d8db5fb88a09dc7ae56f6bbe60c472a7e194b4dec260d5a0341afd317a6df276
use super::Plan;
pub(super) const DEFAULT: Plan = Plan {
    byrate: [
        80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 76, 72, 80, 80, 80, 80, 80, 76, 72, 68, 64, 60, 56,
        52, 80, 80, 80, 80, 80, 80, 80, 80, 80, 76, 72, 68, 64, 60, 56, 52, 80, 80, 80, 80,
    ],
    offset: [0, 0, 0, 0, 0],
    limits: [[56, 0, 0, 0, 58, 0, 58, 0], [44, 0, 0, 0, 46, 0, 46, 34]],
    ru: [[32, 42, 56], [20, 32, 44]],
    shape: [0, 0],
};
