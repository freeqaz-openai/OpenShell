// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-operation external STATIC credential custody and final authorization.
//!
//! This module never caches material or permits, starts issuance, or retries an
//! RPC. The authority owns source semantics and both independent online checks.

use std::time::{Duration, SystemTime};

use futures::StreamExt;
use miette::{Result, miette};
use openshell_core::extension_protocol::credential_enforcement_profile;
use openshell_core::middleware::{InstallationReplyStream, VerifiedCredentialOrigin};
use openshell_core::proto::{
    HttpCredentialAuthorizeSendRequest, HttpCredentialMaterial, HttpCredentialResolveRequest,
    HttpHeader, HttpNoMaterialRequired, HttpRequestEvaluation, RequestContext,
    SupervisorMiddlewareOperation as Operation, SupervisorMiddlewarePhase as Phase,
    http_credential_authorize_send_request::Selection as SendSelection,
    http_credential_authorize_send_response,
    http_credential_resolve_response::Result as AccessSelection,
};
use openshell_core::proto::{
    InstallationExchangeOpen, InstallationExchangeRequest, InstallationExchangeResponse,
    installation_exchange_reply::Event as Reply,
    installation_exchange_request::Event as ExchangeRequest,
};
use openshell_extension_core::InstallationSigningKey;
use prost::Message;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::remote::GrpcMiddlewareService;
use crate::{ChainEntry, ChainRunner, MiddlewareDispatch, OnError};

pub const MAX_CREDENTIAL_OPERATION_TIME: Duration =
    openshell_core::middleware::MAX_HTTP_CREDENTIAL_OPERATION_TIME;
const MAX_CREDENTIAL_BYTES: usize = 32 * 1024;
const MAX_OPERATION_HANDLE_BYTES: usize = 4096;

/// Selection is explicit policy, independent of service availability.
pub fn has_credential_authority(entries: &[ChainEntry]) -> bool {
    entries.iter().any(|entry| entry.credential_authority)
}

/// One validated, authenticated authority selected by the current policy.
/// Material and permits are deliberately neither Debug nor Clone.
pub struct CredentialAuthority {
    policy: CredentialAuthorityPolicy,
    installation_key: InstallationSigningKey,
}

/// An admissible policy binding, not authority to start an installation exchange.
pub(super) struct CredentialAuthorityPolicy {
    service: GrpcMiddlewareService,
    entry: ChainEntry,
    audience: String,
    timeout: Duration,
    max_payload_bytes: usize,
}

impl ChainRunner {
    /// Refuse ambiguity, missing capability, insecure transport and fail-open
    /// independently of ordinary middleware's optional binding semantics.
    pub async fn credential_authority(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Option<CredentialAuthority>> {
        let Some(policy) = self.credential_authority_policy(entries).await? else {
            return Ok(None);
        };
        let installation_key = policy.service.installation_key.clone().ok_or_else(|| {
            miette!("credential authority requires local installation possession")
        })?;
        Ok(Some(CredentialAuthority {
            policy,
            installation_key,
        }))
    }

    /// Check the same binding at gateway admission and supervisor enforcement. Only the
    /// enforcing supervisor can construct a `CredentialAuthority` with its local installation key.
    pub(super) async fn credential_authority_policy(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Option<CredentialAuthorityPolicy>> {
        let mut selected = entries.iter().filter(|entry| entry.credential_authority);
        let Some(entry) = selected.next() else {
            return Ok(None);
        };
        if selected.next().is_some() || entry.on_error != OnError::FailClosed {
            return Err(miette!("credential authority selection refused"));
        }
        let manifests = self.manifests().await?;
        let (state, manifest) = manifests
            .iter()
            .find(|(state, manifest)| {
                Self::attachment_name(state, manifest) == entry.implementation
            })
            .ok_or_else(|| miette!("credential authority is unavailable"))?;
        let audience = state
            .credential_audience
            .clone()
            .ok_or_else(|| miette!("credential authority requires authenticated TLS"))?;
        let MiddlewareDispatch::Grpc(service) = &state.service else {
            return Err(miette!("credential authority requires authenticated TLS"));
        };
        // This version cannot compose another response policy on the protected exchange.
        if entries.len() != 1 {
            return Err(miette!(
                "protected response policy must have unambiguous exclusive custody"
            ));
        }
        let binding = Self::binding(manifest, Operation::HttpCredentials, Phase::PreCredentials)
            .ok_or_else(|| miette!("credential authority capability is unavailable"))?;
        if Self::binding(manifest, Operation::HttpResponse, Phase::PreReturn).is_none()
            || !manifest.extension.as_ref().is_some_and(|metadata| {
                credential_enforcement_profile(entry.execution_authority)
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
                "credential authority requires response policy and protocol capability"
            ));
        }
        Ok(Some(CredentialAuthorityPolicy {
            service: service.clone(),
            entry: entry.clone(),
            audience,
            timeout: state.timeout_for_binding(binding)?,
            max_payload_bytes: state.operator_max_payload_bytes.unwrap_or(
                crate::validate_payload_limit("credential authority", binding)?,
            ),
        }))
    }
}

impl CredentialAuthority {
    pub fn max_payload_bytes(&self) -> usize {
        self.policy.max_payload_bytes
    }

    /// Capture/check-before-access/resolve are one authority transaction. The
    /// subsequent send check is a distinct RPC and must use current policy.
    pub async fn resolve(
        self,
        mut evaluation: HttpRequestEvaluation,
        deadline: SystemTime,
        response_custody: &[u8; 32],
        origin: VerifiedCredentialOrigin,
    ) -> Result<SelectedCredential> {
        let now = SystemTime::now();
        let remaining = deadline
            .duration_since(now)
            .map_err(|_| miette!("credential operation deadline exceeded"))?;
        if remaining > MAX_CREDENTIAL_OPERATION_TIME {
            return Err(miette!(
                "credential operation deadline exceeds platform bound"
            ));
        }
        let mut context = evaluation
            .context
            .clone()
            .ok_or_else(|| miette!("credential operation identity is missing"))?;
        let verified_execution_policy_hash = match origin {
            VerifiedCredentialOrigin::Execution { policy_hash }
                if self.policy.entry.execution_authority
                    && context.verified_credential_connector.is_none()
                    && policy_hash.len() == 64
                    && policy_hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                policy_hash
            }
            VerifiedCredentialOrigin::Connector(proof)
                if !self.policy.entry.execution_authority
                    && context
                        .verified_credential_connector
                        .as_ref()
                        .is_none_or(|existing| existing == &proof)
                    && openshell_core::middleware::valid_credential_connector(
                        &proof.path,
                        &proof.sha256,
                    )
                    && !proof.policy_hash.is_empty() =>
            {
                context.verified_credential_connector = Some(proof);
                String::new()
            }
            _ => {
                return Err(miette!(
                    "credential admission does not match policy authority profile"
                ));
            }
        };
        if context.request_id.is_empty() || context.sandbox_id.is_empty() {
            return Err(miette!("credential operation identity is missing"));
        }
        evaluation.context = Some(context.clone());
        let horizon =
            openshell_core::middleware::http_credential_operation_horizon(&context.request_id, now)
                .ok_or_else(|| {
                    miette!("credential operation requires a current canonical UUIDv7")
                })?;
        if deadline > horizon || deadline <= horizon - MAX_CREDENTIAL_OPERATION_TIME {
            return Err(miette!(
                "credential deadline exceeds immutable operation horizon"
            ));
        }
        if evaluation
            .target
            .as_ref()
            .is_none_or(|target| target.scheme != "https")
        {
            return Err(miette!("credential authority requires HTTPS"));
        }
        evaluation.middleware_name = self.policy.entry.implementation.clone();
        evaluation.config = Some(self.policy.entry.config.clone());
        evaluation.phase = Phase::PreCredentials as i32;
        if evaluation.body.len() > self.policy.max_payload_bytes
            || evaluation.encoded_len() > crate::MIDDLEWARE_GRPC_MESSAGE_BYTES
        {
            return Err(miette!("credential operation exceeds capacity"));
        }
        let opening = HttpCredentialResolveRequest {
            request: Some(evaluation),
            deadline: Some(deadline.into()),
            audience: self.policy.audience.clone(),
            response_custody: response_custody.to_vec(),
            verified_execution_policy_hash,
        }
        .encode_to_vec();
        let timeout = self.policy.timeout.min(remaining);
        let (exchange, response) = tokio::time::timeout(timeout, async {
            let (requests, receiver) = tokio::sync::mpsc::channel(1);
            let replies = self
                .policy
                .service
                .open_installation_exchange(receiver)
                .await
                .map_err(|_| miette!("installation exchange refused"))?;
            let mut exchange = InstallationExchange {
                requests,
                replies,
                timeout: self.policy.timeout,
                custody: *response_custody,
            };
            let Reply::Challenge(challenge) = exchange.receive().await? else {
                return Err(miette!("installation challenge missing"));
            };
            let challenge = challenge
                .as_slice()
                .try_into()
                .map_err(|_| miette!("installation challenge invalid"))?;
            let signature = self.installation_key.sign_opening(challenge, &opening);
            send_exchange(
                &exchange.requests,
                ExchangeRequest::Open(InstallationExchangeOpen {
                    resolve_request: opening,
                    signature,
                }),
            )
            .await?;
            let Reply::Resolved(response) = exchange.receive().await? else {
                return Err(miette!("installation resolution missing"));
            };
            Ok((exchange, response))
        })
        .await
        .map_err(|_| miette!("installation resolution timed out"))??;
        let selection = match response.result {
            Some(AccessSelection::Ready(material)) => Selection::Material(material),
            Some(AccessSelection::ReadyWithoutMaterial(operation))
                if self.policy.entry.execution_authority =>
            {
                Selection::NoMaterialRequired(operation)
            }
            _ => return Err(miette!("credential resolution refused")),
        };
        // Take custody immediately so every validation/error path erases selected values.
        let selected = SelectedCredential {
            authority: self,
            context,
            deadline,
            selection,
            exchange,
        };
        selected.validate()?;
        Ok(selected)
    }
}

/// Request-bound authority selection. Either arm requires the same committed send and response custody.
pub struct SelectedCredential {
    authority: CredentialAuthority,
    context: RequestContext,
    deadline: SystemTime,
    selection: Selection,
    exchange: InstallationExchange,
}

// No empty credential, invented evidence, or missing-material fallback.
enum Selection {
    Material(HttpCredentialMaterial),
    NoMaterialRequired(HttpNoMaterialRequired),
}

impl Drop for Selection {
    fn drop(&mut self) {
        match self {
            Self::Material(material) => {
                for header in &mut material.credential_headers {
                    header.value.zeroize();
                }
                material.operation_handle.zeroize();
            }
            Self::NoMaterialRequired(operation) => operation.operation_handle.zeroize(),
        }
    }
}

impl SelectedCredential {
    fn validate(&self) -> Result<()> {
        let (id, audience, handle) = match &self.selection {
            Selection::Material(m) => (&m.request_id, &m.audience, &m.operation_handle),
            Selection::NoMaterialRequired(m) => (&m.request_id, &m.audience, &m.operation_handle),
        };
        if id != &self.context.request_id
            || audience != &self.authority.policy.audience
            || handle.is_empty()
            || handle.len() > MAX_OPERATION_HANDLE_BYTES
            || SystemTime::now() >= self.deadline
        {
            return Err(miette!("protected operation binding invalid"));
        }
        let Selection::Material(material) = &self.selection else {
            return Ok(());
        };
        if material.credential_headers.is_empty()
            || material.credential_headers.len() > 3
            || material.encoded_len() > MAX_CREDENTIAL_BYTES * 3
        {
            return Err(miette!("credential material binding invalid"));
        }
        let evidence = material
            .evidence
            .as_ref()
            .ok_or_else(|| miette!("credential evidence is missing"))?;
        if evidence.material_id.is_empty()
            || evidence.material_id.len() > 1024
            || evidence.material_version.is_empty()
            || evidence.material_version.len() > 1024
            || evidence.authority_evidence.is_empty()
            || evidence.authority_evidence.len() > MAX_CREDENTIAL_BYTES
        {
            return Err(miette!("credential evidence invalid"));
        }
        let usable = timestamp(evidence.usable_until.as_ref())?;
        if usable <= SystemTime::now() || usable > self.deadline {
            return Err(miette!("credential material is not usable"));
        }
        let mut names = std::collections::HashSet::new();
        for header in &material.credential_headers {
            if !is_credential_header(&header.name)
                || !names.insert(&header.name)
                || header.value.is_empty()
                || header.value.len() > MAX_CREDENTIAL_BYTES
                || !header
                    .value
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte))
                || openshell_core::secrets::contains_reserved_credential_marker(&header.value)
            {
                return Err(miette!("credential injection invalid"));
            }
        }
        Ok(())
    }

    /// Explicitly selected by the authority, never deduced from missing credential headers.
    pub fn no_material_required(&self) -> bool {
        matches!(self.selection, Selection::NoMaterialRequired(_))
    }

    /// The trusted relay constructs its complete outgoing header block before
    /// calling `authorize_send`. No subsequent transform or selection is allowed.
    pub fn headers(&self) -> &[HttpHeader] {
        match &self.selection {
            Selection::Material(m) => &m.credential_headers,
            Selection::NoMaterialRequired(_) => &[],
        }
    }

    pub async fn authorize_send(mut self, live_custody: &[u8; 32]) -> Result<AuthorizedCredential> {
        self.validate()?;
        let digest = credential_headers_sha256(self.headers());
        let remaining = self
            .deadline
            .duration_since(SystemTime::now())
            .map_err(|_| miette!("credential operation deadline exceeded"))?;
        let timeout = self.authority.policy.timeout.min(remaining);
        if &self.exchange.custody != live_custody {
            return Err(miette!("accepted response custody changed"));
        }
        let (handle, selection, usable_until) = match &self.selection {
            Selection::Material(m) => {
                let evidence = m
                    .evidence
                    .as_ref()
                    .ok_or_else(|| miette!("missing evidence"))?;
                (
                    &m.operation_handle,
                    SendSelection::Evidence(evidence.clone()),
                    timestamp(evidence.usable_until.as_ref())?,
                )
            }
            Selection::NoMaterialRequired(operation) => (
                &operation.operation_handle,
                SendSelection::NoMaterialRequired(true),
                self.deadline,
            ),
        };
        let no_material_required = matches!(selection, SendSelection::NoMaterialRequired(true));
        let request = HttpCredentialAuthorizeSendRequest {
            context: Some(self.context.clone()),
            operation_handle: handle.clone(),
            audience: self.authority.policy.audience.clone(),
            deadline: Some(self.deadline.into()),
            selection: Some(selection),
            credential_headers_sha256: digest.to_vec(),
        };
        let response = tokio::time::timeout(timeout, async {
            send_exchange(&self.exchange.requests, ExchangeRequest::Authorize(request)).await?;
            let Reply::Authorized(response) = self.exchange.receive().await? else {
                return Err(miette!("installation authorization missing"));
            };
            Ok(response)
        })
        .await
        .map_err(|_| miette!("credential authorization timed out"))??;
        let Some(http_credential_authorize_send_response::Result::Allowed(permit)) =
            response.result
        else {
            return Err(miette!("credential authorization refused"));
        };
        let send_start_by = timestamp(permit.send_start_by.as_ref())?;
        if permit.request_id != self.context.request_id
            || permit.operation_handle != *handle
            || permit.no_material_required != no_material_required
            || permit.credential_headers_sha256 != digest
            || permit.response_custody != *live_custody
            || send_start_by > self.deadline
            || send_start_by > usable_until
        {
            return Err(miette!("credential send permit binding invalid"));
        }
        let authorized = AuthorizedCredential {
            selected: self,
            send_start_by,
        };
        authorized.ensure_current(live_custody)?;
        Ok(authorized)
    }
}

/// One non-cloneable send authorization for this exact selection and response custody.
pub struct AuthorizedCredential {
    selected: SelectedCredential,
    send_start_by: SystemTime,
}

impl AuthorizedCredential {
    fn ensure_current(&self, live_custody: &[u8; 32]) -> Result<()> {
        if &self.selected.exchange.custody != live_custody {
            return Err(miette!("send permit does not match live response custody"));
        }
        self.selected.validate()?;
        if SystemTime::now() >= self.send_start_by {
            return Err(miette!("credential send permit expired"));
        }
        Ok(())
    }

    /// Bound the origin's actual first write; later polls cannot extend the authorized start.
    pub fn send_start_by(&self) -> SystemTime {
        self.send_start_by
    }

    /// Consume this one permit. A closed authority stream wins over any pending dispatch;
    /// neither an interrupted send nor a lost return can start a second operation here.
    pub async fn dispatch_and_protect(
        mut self,
        live_custody: &[u8; 32],
        dispatch: impl Future<Output = Result<InstallationExchangeResponse>>,
    ) -> Result<InstallationExchangeResponse> {
        self.ensure_current(live_custody)?;
        let exchange = &mut self.selected.exchange;
        let captured = tokio::select! {
            biased;
            _ = exchange.replies.next() => return Err(miette!("installation closed before complete response")),
            result = dispatch => result?,
        };
        if !captured.response_complete {
            return Err(miette!("origin response incomplete"));
        }
        tokio::time::timeout(exchange.timeout, async {
            send_exchange(&exchange.requests, ExchangeRequest::Response(captured)).await?;
            let Reply::Response(approved) = exchange.receive().await? else {
                return Err(miette!("response policy approval missing"));
            };
            // A successful terminal status excludes a partial, failed or ambiguous policy reply.
            if !approved.response_complete
                || exchange.replies.next().await.is_some()
                || &exchange.custody != live_custody
            {
                return Err(miette!(
                    "response policy did not finish for accepted custody"
                ));
            }
            Ok(approved)
        })
        .await
        .map_err(|_| miette!("response policy approval timed out"))?
    }
}

struct InstallationExchange {
    requests: tokio::sync::mpsc::Sender<InstallationExchangeRequest>,
    replies: InstallationReplyStream,
    custody: [u8; 32],
    timeout: Duration,
}

async fn send_exchange(
    requests: &tokio::sync::mpsc::Sender<InstallationExchangeRequest>,
    event: ExchangeRequest,
) -> Result<()> {
    requests
        .send(InstallationExchangeRequest { event: Some(event) })
        .await
        .map_err(|_| miette!("installation exchange closed"))
}

impl InstallationExchange {
    async fn receive(&mut self) -> Result<Reply> {
        self.replies
            .next()
            .await
            .and_then(std::result::Result::ok)
            .and_then(|reply| reply.event)
            .ok_or_else(|| miette!("installation exchange incomplete"))
    }
}

pub fn is_credential_header(name: &str) -> bool {
    matches!(name, "authorization" | "x-api-key" | "api-key")
}

pub fn credential_headers_sha256(headers: &[HttpHeader]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for header in headers {
        for value in [&header.name, &header.value] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    digest.finalize().into()
}

fn timestamp(value: Option<&prost_types::Timestamp>) -> Result<SystemTime> {
    let value = value.ok_or_else(|| miette!("credential timestamp is missing"))?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(miette!("credential timestamp invalid"));
    }
    SystemTime::try_from(*value).map_err(|_| miette!("credential timestamp invalid"))
}
