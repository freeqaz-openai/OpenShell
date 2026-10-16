// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Non-exportable, process-local possession used by the supervisor installation exchange.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use std::sync::Arc;

/// JWT key profile for terminal HTTP exchange.
pub const HTTP_EXCHANGE_KEY_PROFILE: &str = "openshell-http-exchange-v1";

/// Clones share possession within the trusted supervisor; no private-key accessor or serializer.
#[derive(Clone)]
pub struct InstallationSigningKey(Arc<Ed25519KeyPair>);

impl InstallationSigningKey {
    pub fn generate() -> Result<Self, aws_lc_rs::error::Unspecified> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        Ok(Self(Arc::new(Ed25519KeyPair::from_pkcs8(doc.as_ref())?)))
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    /// Sign exactly the bytes transmitted, bound to the challenge from this response stream.
    #[must_use]
    pub fn sign_opening(&self, challenge: &[u8; 32], opening: &[u8]) -> Vec<u8> {
        let mut transcript = Vec::from(HTTP_EXCHANGE_KEY_PROFILE.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(challenge);
        transcript.extend_from_slice(opening);
        self.0.sign(&transcript).as_ref().to_vec()
    }
}

/// Generate a new opaque commitment, never a transferable response destination.
pub fn new_response_custody() -> Result<[u8; 32], aws_lc_rs::error::Unspecified> {
    let mut custody = [0; 32];
    SystemRandom::new().fill(&mut custody)?;
    Ok(custody)
}
