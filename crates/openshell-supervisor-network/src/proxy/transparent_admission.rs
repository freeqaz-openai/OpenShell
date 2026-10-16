// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Proof confined to the backend's blocked-connect admission path.
/// Explicit proxy identities and later procfs lookups cannot construct it.
pub(crate) struct VerifiedTransparentConnect {
    generation: u64,
}

impl VerifiedTransparentConnect {
    pub(super) fn new(generation: u64) -> Self {
        Self { generation }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}
