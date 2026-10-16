// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proposed terminal exchange with an explicitly trusted external HTTP authority.
//! No provider credential, permit, or provider-specific evidence enters OpenShell.

use crate::remote::GrpcMiddlewareService;
use crate::{ChainEntry, ChainRunner, MiddlewareDispatch, OnError};
use futures::StreamExt;
use miette::{Result, miette};
use openshell_core::extension_protocol::external_http_exchange_capabilities;
use openshell_core::middleware::VerifiedExchangeOrigin;
use openshell_core::proto::{
    HttpExchangeOpening, HttpRequestEvaluation, InstallationExchangeOpen,
    InstallationExchangeRequest, InstallationExchangeResponse,
    SupervisorMiddlewareOperation as Operation, SupervisorMiddlewarePhase as Phase,
    installation_exchange_reply::Event as Reply,
    installation_exchange_request::Event as ExchangeRequest,
};
use openshell_extension_core::InstallationSigningKey;
use prost::Message;
use std::time::{Duration, SystemTime};

pub const MAX_HTTP_EXCHANGE_OPERATION_TIME: Duration =
    openshell_core::middleware::MAX_HTTP_EXCHANGE_OPERATION_TIME;

/// Selection is explicit policy, independent of service availability.
pub fn has_external_http_exchange(entries: &[ChainEntry]) -> bool {
    entries.iter().any(|entry| entry.external_http_exchange)
}

/// One validated, authenticated authority selected by the current policy.
/// The signed opening is single-use and never retried.
pub struct HttpExchangeAuthority {
    policy: HttpExchangePolicy,
    installation_key: InstallationSigningKey,
}

/// An admissible policy binding, not authority to start an installation exchange.
pub(super) struct HttpExchangePolicy {
    service: GrpcMiddlewareService,
    entry: ChainEntry,
    audience: String,
    timeout: Duration,
    max_payload_bytes: usize,
}

impl ChainRunner {
    /// Refuse ambiguity, missing capability, insecure transport and fail-open
    /// independently of ordinary middleware's optional binding semantics.
    pub async fn http_exchange_authority(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Option<HttpExchangeAuthority>> {
        let Some(policy) = self.http_exchange_policy(entries).await? else {
            return Ok(None);
        };
        let installation_key = policy.service.installation_key.clone().ok_or_else(|| {
            miette!("HTTP exchange authority requires local installation possession")
        })?;
        Ok(Some(HttpExchangeAuthority {
            policy,
            installation_key,
        }))
    }

    /// Check the same binding at gateway admission and supervisor enforcement. Only the
    /// enforcing supervisor can construct a `HttpExchangeAuthority` with its local installation key.
    pub(super) async fn http_exchange_policy(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Option<HttpExchangePolicy>> {
        let mut selected = entries.iter().filter(|entry| entry.external_http_exchange);
        let Some(entry) = selected.next() else {
            return Ok(None);
        };
        if selected.next().is_some() || entry.on_error != OnError::FailClosed {
            return Err(miette!("HTTP exchange authority selection refused"));
        }
        let manifests = self.manifests().await?;
        let (state, manifest) = manifests
            .iter()
            .find(|(state, manifest)| {
                Self::attachment_name(state, manifest) == entry.implementation
            })
            .ok_or_else(|| miette!("HTTP exchange authority is unavailable"))?;
        let audience = state
            .credential_audience
            .clone()
            .ok_or_else(|| miette!("HTTP exchange authority requires authenticated TLS"))?;
        let MiddlewareDispatch::Grpc(service) = &state.service else {
            return Err(miette!("HTTP exchange authority requires authenticated TLS"));
        };
        // This version cannot compose another response policy on the protected exchange.
        if entries.len() != 1 {
            return Err(miette!(
                "protected response policy must have unambiguous exclusive custody"
            ));
        }
        let binding = Self::binding(manifest, Operation::HttpExchange, Phase::PreCredentials)
            .ok_or_else(|| miette!("HTTP exchange authority capability is unavailable"))?;
        if manifest.bindings.len() != 1
            || !manifest.extension.as_ref().is_some_and(|metadata| {
                external_http_exchange_capabilities()
                    .iter()
                    .all(|capability| {
                        metadata
                            .supported_capabilities
                            .iter()
                            .any(|value| value == capability)
                            && metadata
                                .required_capabilities
                                .iter()
                                .any(|value| value == capability)
                    })
            })
        {
            return Err(miette!(
                "HTTP exchange authority requires terminal exchange capability"
            ));
        }
        Ok(Some(HttpExchangePolicy {
            service: service.clone(),
            entry: entry.clone(),
            audience,
            timeout: state.timeout_for_binding(binding)?,
            max_payload_bytes: state.operator_max_payload_bytes.unwrap_or(
                crate::validate_payload_limit("HTTP exchange authority", binding)?,
            ),
        }))
    }
}

impl HttpExchangeAuthority {
    pub fn max_payload_bytes(&self) -> usize {
        self.policy.max_payload_bytes
    }

    /// Consume this operation. After opening, any failure has an unknown remote
    /// outcome; callers must never retry or fall back to an origin connection.
    pub async fn exchange(
        self,
        mut evaluation: HttpRequestEvaluation,
        deadline: SystemTime,
        response_custody: &[u8; 32],
        origin: VerifiedExchangeOrigin,
    ) -> Result<InstallationExchangeResponse> {
        let now = SystemTime::now();
        let context = evaluation
            .context
            .as_ref()
            .ok_or_else(|| miette!("exchange identity missing"))?;
        let horizon =
            openshell_core::middleware::http_exchange_operation_horizon(&context.request_id, now)
                .ok_or_else(|| miette!("exchange requires current canonical UUIDv7"))?;
        let VerifiedExchangeOrigin { policy_hash } = origin;
        if context.sandbox_id.is_empty()
            || policy_hash.len() != 64
            || !policy_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || deadline > horizon
            || deadline <= now
            || deadline > now + MAX_HTTP_EXCHANGE_OPERATION_TIME
            || evaluation
                .target
                .as_ref()
                .is_none_or(|t| t.scheme != "https")
        {
            return Err(miette!("exchange admission invalid"));
        }
        evaluation.middleware_name = self.policy.entry.implementation.clone();
        evaluation.config = Some(self.policy.entry.config.clone());
        evaluation.phase = Phase::PreCredentials as i32;
        if evaluation.body.len() > self.policy.max_payload_bytes
            || evaluation.encoded_len() > crate::MIDDLEWARE_GRPC_MESSAGE_BYTES
        {
            return Err(miette!("exchange exceeds capacity"));
        }
        let opening = HttpExchangeOpening {
            request: Some(evaluation),
            deadline: Some(deadline.into()),
            audience: self.policy.audience.clone(),
            response_custody: response_custody.to_vec(),
            verified_execution_policy_hash: policy_hash,
        }
        .encode_to_vec();
        let timeout = self
            .policy
            .timeout
            .min(deadline.duration_since(now).unwrap_or_default());
        tokio::time::timeout(timeout, async {
            let (requests, receiver) = tokio::sync::mpsc::channel(1);
            let mut replies = self
                .policy
                .service
                .open_installation_exchange(receiver)
                .await
                .map_err(|_| miette!("exchange refused"))?;
            let Some(Ok(reply)) = replies.next().await else {
                return Err(miette!("exchange challenge missing"));
            };
            let Some(Reply::Challenge(challenge)) = reply.event else {
                return Err(miette!("exchange challenge missing"));
            };
            let challenge = challenge
                .as_slice()
                .try_into()
                .map_err(|_| miette!("exchange challenge invalid"))?;
            let signature = self.installation_key.sign_opening(challenge, &opening);
            requests
                .send(InstallationExchangeRequest {
                    event: Some(ExchangeRequest::Open(InstallationExchangeOpen {
                        opening,
                        signature,
                    })),
                })
                .await
                .map_err(|_| miette!("exchange closed"))?;
            // One opening only. The reply stream remains held by this live future.
            drop(requests);
            let Some(Ok(reply)) = replies.next().await else {
                return Err(miette!("exchange incomplete"));
            };
            let Some(Reply::Response(response)) = reply.event else {
                return Err(miette!("exchange refused"));
            };
            validate_response(&response, self.policy.max_payload_bytes)?;
            // None means the gRPC decoder observed terminal OK. An extra reply or
            // error (including non-OK trailers after a response) blocks all output.
            if replies.next().await.is_some() {
                return Err(miette!("exchange terminal status invalid"));
            }
            Ok(response)
        })
        .await
        .map_err(|_| miette!("exchange timed out"))?
    }
}

fn validate_response(response: &InstallationExchangeResponse, limit: usize) -> Result<()> {
    if !response.response_complete
        || !(200..=599).contains(&response.status)
        || response.body.len() > limit.min(crate::MAX_MIDDLEWARE_PAYLOAD_BYTES)
        || response.content_type.len() > 256
        || response.content_type.is_empty()
        || !response
            .content_type
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b))
        || (matches!(response.status, 204 | 205 | 304) && !response.body.is_empty())
    {
        return Err(miette!("exchange response invalid"));
    }
    Ok(())
}
