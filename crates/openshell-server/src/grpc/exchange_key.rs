// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Key custody metadata captured from an already authenticated supervisor hello.
//! This value cannot authenticate a hello; the session boundary owns that check.

#[derive(Clone, Debug)]
pub(crate) struct EnrolledExchangeKey {
    instance: String,
    key: [u8; 32],
}

impl EnrolledExchangeKey {
    pub(crate) fn capture(instance: &str, key: &[u8]) -> Result<Option<Self>, &'static str> {
        if key.is_empty() {
            return Ok(None);
        }
        if instance.is_empty() {
            return Err("exchange key requires a supervisor instance");
        }
        let key = key.try_into().map_err(|_| "invalid exchange public key")?;
        Ok(Some(Self {
            instance: instance.to_owned(),
            key,
        }))
    }

    pub(crate) fn for_instance(&self, current: &str) -> Option<&[u8]> {
        (self.instance == current).then_some(self.key.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::EnrolledExchangeKey;

    #[test]
    fn captured_key_cannot_be_retargeted_by_current_state_or_mutated_input() {
        let mut input = [7; 32];
        let enrolled = EnrolledExchangeKey::capture("installation-a", &input)
            .unwrap()
            .unwrap();
        input.fill(9);
        assert_eq!(enrolled.for_instance("installation-a"), Some(&[7; 32][..]));
        assert_eq!(enrolled.for_instance("installation-b"), None);
    }

    #[test]
    fn legacy_hello_has_no_key_and_malformed_enrollment_fails() {
        assert!(
            EnrolledExchangeKey::capture("installation-a", &[])
                .unwrap()
                .is_none()
        );
        assert!(EnrolledExchangeKey::capture("installation-a", &[7; 31]).is_err());
        assert!(EnrolledExchangeKey::capture("", &[7; 32]).is_err());
    }
}
