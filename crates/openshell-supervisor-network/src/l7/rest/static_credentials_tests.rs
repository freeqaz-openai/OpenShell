// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real TLS/gRPC authority and TLS provider tests of the production relay. The
//! authority fixture models revocation and operation binding, not external IAM.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use openshell_core::extension_protocol::{
    ExtensionFamily, HTTP_CREDENTIAL_REQUIRED_CAPABILITIES, credential_enforcement_profile,
    extension_metadata,
};
use openshell_core::proto::http_credential_authorize_send_request::Selection as SendSelection;
use openshell_core::proto::middleware::v1::{
    http_credential_access_server::HttpCredentialAccess,
    http_installation_exchange_server::{HttpInstallationExchange, HttpInstallationExchangeServer},
    supervisor_middleware_server::{SupervisorMiddleware, SupervisorMiddlewareServer},
};
use openshell_core::proto::*;
use openshell_extension_core::{
    BearerTokenSlot, EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims,
};
use openshell_supervisor_middleware::{ChainEntry, ChainRunner, MiddlewareRegistry, OnError};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use super::*;
use crate::l7::provider::BodyLength;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_core::middleware::VerifiedCredentialOrigin;
use openshell_extension_core::{ExchangeKey, ExtensionCredentialStore};
use prost::Message;

const AUDIENCE: &str = "urn:test:static-credential-authority";
const NO_MATERIAL_PATH: &str = "/protected-read";
const PRIVATE_CANARY: &str = "PRIVATE_NAME_REFUSAL_CANARY_6857";
const REFUSED_RESPONSE: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const SANDBOX: &str = "immutable-sandbox-1";
const INSTANCE: &str = "11111111-1111-4111-8111-111111111111";
const TOKEN: &str = "fixture-static-material-for-tests-only";

#[cfg(target_os = "linux")]
#[path = "connect_credentials_tests.rs"]
mod connect;

#[derive(Clone, Copy, Default)]
enum Behavior {
    #[default]
    Allow,
    ExecutionAllow,
    NoMaterial(NoMaterial),
    PrivateTargetRefusal,
    WrongCustody,
    WrongEnrollment,
    LostAuthorization,
    DownstreamClosedDuringAuthorization,
    MissingCompletion,
    FailedTerminal,
    OldConnector,
    OptionalConnector,
    OldCustodyProfile,
    OptionalCustodyProfile,
    DelayedCapture,
    ExpiredOperation,
    RevokeAfterResolve,
    WrongBinding,
    WrongAudience,
    MissingEvidence,
    EmptyCredentialMaterial,
    MaterialPermitClaimsNoMaterial,
    ExpiredMaterial,
    WrongDigest,
    ExpiredPermit,
    ResolutionUnavailable,
    AuthorizationUnavailable,
    AuthorizationTimeout,
    ResponseBlocked,
    ResponseBodyBlocked,
    ResponseBodyUnavailable,
    ResponseTimeout,
    ResponseNeverEnds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoMaterial {
    Allow,
    MissingHandle,
    WrongSelection,
    NonemptyDigest,
    StaleCustody,
    LostPermit,
    ClosedPeer,
    ChangedRoute,
    WithdrawDuringSend,
    OldCapability,
    OptionalCapability,
    NarrowProfile,
}

impl Behavior {
    fn no_material(self) -> Option<NoMaterial> {
        match self {
            Self::NoMaterial(case) => Some(case),
            _ => None,
        }
    }

    fn execution(self) -> bool {
        matches!(self, Self::ExecutionAllow)
            || self
                .no_material()
                .is_some_and(|case| case != NoMaterial::NarrowProfile)
    }
}

#[derive(Clone)]
struct Authority {
    expected_proof: Arc<Mutex<Option<VerifiedCredentialConnector>>>,
    contexts: Arc<Mutex<HashMap<Vec<u8>, RequestContext>>>,
    expected_host: String,
    key: DecodingKey,
    behavior: Behavior,
    payload_limit: u64,
    revoked: Arc<AtomicBool>,
    selected: Arc<Mutex<HashMap<Vec<u8>, HttpCredentialMaterial>>>,
    resolutions: Arc<AtomicUsize>,
    authorizations: Arc<AtomicUsize>,
    access_grants: Arc<AtomicUsize>,
    material_reads: Arc<AtomicUsize>,
    send_grants: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
    response_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    response_trailers: Arc<Mutex<Vec<Vec<HttpHeader>>>>,
    before_send: Arc<Notify>,
    continue_send: Arc<Notify>,
}

impl Authority {
    fn authenticate<T>(&self, request: &Request<T>) -> Result<ExtensionJwtClaims, Status> {
        let bearer = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&["test-gateway"]);
        let decoded = decode::<ExtensionJwtClaims>(bearer, &self.key, &validation)
            .map_err(|_| Status::unauthenticated("invalid"))?;
        if decoded.header.typ.as_deref() != Some(EXTENSION_JWT_TYP)
            || decoded.claims.caller_kind != ExtensionCallerKind::Supervisor
            || decoded.claims.sandbox_id.as_deref() != Some(SANDBOX)
            || decoded.claims.instance_id.as_deref() != Some(INSTANCE)
            || decoded.claims.sub != format!("spiffe://openshell/sandbox/{SANDBOX}")
        {
            return Err(Status::unauthenticated("identity"));
        }
        Ok(decoded.claims)
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for Authority {
    type EvaluateWebSocketSessionStream =
        ReceiverStream<Result<WebSocketSessionEventResult, Status>>;
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        self.authenticate(&request)?;
        let profile = credential_enforcement_profile(self.behavior.execution());
        let peer = request.get_ref().gateway.as_ref().unwrap();
        assert!(
            profile
                .iter()
                .all(|cap| peer.supported_capabilities.iter().any(|v| v == cap))
        );
        let mut metadata = extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            "test/authority",
            "1",
            profile.iter().copied().map(str::to_string),
        );
        metadata
            .required_capabilities
            .extend(profile.iter().copied().map(str::to_string));
        if matches!(self.behavior, Behavior::OldConnector) {
            metadata
                .supported_capabilities
                .retain(|value| value != HTTP_CREDENTIAL_REQUIRED_CAPABILITIES[1]);
            metadata
                .required_capabilities
                .retain(|value| value != HTTP_CREDENTIAL_REQUIRED_CAPABILITIES[1]);
        }
        if matches!(self.behavior, Behavior::OptionalConnector) {
            metadata
                .required_capabilities
                .retain(|value| value != HTTP_CREDENTIAL_REQUIRED_CAPABILITIES[1]);
        }
        if matches!(
            self.behavior,
            Behavior::OldCustodyProfile | Behavior::OptionalCustodyProfile
        ) {
            let custody = openshell_core::extension_protocol::HTTP_RESPONSE_CUSTODY_CAPABILITY;
            if matches!(self.behavior, Behavior::OldCustodyProfile) {
                metadata.supported_capabilities.retain(|v| v != custody);
            }
            metadata.required_capabilities.retain(|v| v != custody);
        }
        if let Some(case @ (NoMaterial::OldCapability | NoMaterial::OptionalCapability)) =
            self.behavior.no_material()
        {
            let capability =
                openshell_core::extension_protocol::HTTP_PROTECTED_NO_MATERIAL_CAPABILITY;
            metadata.required_capabilities.retain(|v| v != capability);
            if case == NoMaterial::OldCapability {
                metadata.supported_capabilities.retain(|v| v != capability);
            }
        }
        Ok(Response::new(MiddlewareManifest {
            name: "test/authority".into(),
            service_version: "1".into(),
            expected_audience: AUDIENCE.into(),
            extension: Some(metadata),
            bindings: vec![
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpCredentials as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: self.payload_limit,
                    request_timeout: None,
                },
                MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: self.payload_limit,
                    request_timeout: None,
                },
            ],
        }))
    }
    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.authenticate(&request)?;
        Ok(Response::new(ValidateConfigResponse {
            valid: true,
            reason: String::new(),
        }))
    }
    async fn evaluate_http_request(
        &self,
        _: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented("no request binding"))
    }
    async fn evaluate_web_socket_session(
        &self,
        _: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented("no websocket binding"))
    }
}

#[tonic::async_trait]
impl HttpCredentialAccess for Authority {
    async fn resolve(
        &self,
        request: Request<HttpCredentialResolveRequest>,
    ) -> Result<Response<HttpCredentialResolveResponse>, Status> {
        self.authenticate(&request)?;
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        if matches!(self.behavior, Behavior::ResolutionUnavailable) {
            return Err(Status::unavailable("fixture unavailable"));
        }
        let request = request.into_inner();
        let operation = request
            .request
            .ok_or_else(|| Status::invalid_argument("request"))?;
        let context = operation
            .context
            .ok_or_else(|| Status::invalid_argument("context"))?;
        // Independent wire oracle: read the UUID's first six bytes directly,
        // rather than call the production horizon validator.
        let uuid = uuid::Uuid::parse_str(&context.request_id).unwrap();
        assert_eq!(uuid.get_version_num(), 7);
        let created_ms = uuid.as_bytes()[..6]
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        let wire_deadline = request.deadline.as_ref().unwrap();
        let deadline_ms = u64::try_from(wire_deadline.seconds).unwrap() * 1000
            + u64::try_from(wire_deadline.nanos).unwrap() / 1_000_000;
        assert!(created_ms < deadline_ms && deadline_ms <= created_ms + 30_000);
        if matches!(self.behavior, Behavior::DelayedCapture) {
            println!(
                "SUPPLIER_OPERATION_VECTOR {}",
                serde_json::json!({
                    "qualification": "decoded genuine TLS/gRPC fixture request, not installed evidence",
                    "request_context": {"request_id": context.request_id, "sandbox_id": context.sandbox_id},
                    "verified_instance_id": INSTANCE,
                    "creation_ms": created_ms,
                    "deadline": {"seconds": wire_deadline.seconds.to_string(), "nanos": wire_deadline.nanos},
                    "deadline_ms": deadline_ms,
                    "capture_delay_ms": 100,
                    "fixed_horizon_ms": created_ms + 30_000,
                })
            );
        }
        let expected = self.expected_proof.lock().unwrap().clone().unwrap();
        let proof_ok = if self.behavior.execution() {
            context.verified_credential_connector.is_none()
                && request.verified_execution_policy_hash == expected.policy_hash
        } else {
            request.verified_execution_policy_hash.is_empty()
                && context.verified_credential_connector.as_ref() == Some(&expected)
        };
        // The fixture authority owns the admitted route and its material requirement.
        // It never consults a workload selector or tries a material read to decide this.
        let no_material = self.behavior.no_material();
        let (method, path, body) = if no_material.is_some() {
            ("GET", NO_MATERIAL_PATH, b"".as_slice())
        } else {
            (
                "POST",
                "/generate",
                br#"{"model":"fixture-model"}"#.as_slice(),
            )
        };
        if !proof_ok
            || request.response_custody.len() != 32
            || request.audience != AUDIENCE
            || context.sandbox_id != SANDBOX
            || context.request_id.is_empty()
            || operation.body != body
            || operation.target.as_ref().is_none_or(|t| {
                t.scheme != "https"
                    || t.host != self.expected_host
                    || t.port != 443
                    || t.method != method
                    || t.path != path
                    || !t.query.is_empty()
            })
            || operation
                .headers
                .iter()
                .any(|h| is_credential_header(&h.name))
        {
            return Err(Status::permission_denied("capture mismatch"));
        }
        if self.revoked.load(Ordering::SeqCst) {
            return Err(Status::permission_denied("last route withdrawn"));
        }
        self.access_grants.fetch_add(1, Ordering::SeqCst);
        let handle = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.contexts
            .lock()
            .unwrap()
            .insert(handle.clone(), context.clone());
        if let Some(case) = no_material {
            let operation = HttpNoMaterialRequired {
                request_id: context.request_id,
                audience: AUDIENCE.into(),
                operation_handle: if case == NoMaterial::MissingHandle {
                    vec![]
                } else {
                    handle
                },
            };
            return Ok(Response::new(HttpCredentialResolveResponse {
                result: Some(
                    http_credential_resolve_response::Result::ReadyWithoutMaterial(operation),
                ),
            }));
        }
        self.material_reads.fetch_add(1, Ordering::SeqCst);
        let mut material = HttpCredentialMaterial {
            request_id: if matches!(self.behavior, Behavior::WrongBinding) {
                "foreign-operation".into()
            } else {
                context.request_id
            },
            operation_handle: handle.clone(),
            audience: AUDIENCE.into(),
            evidence: Some(HttpCredentialEvidence {
                material_id: "fixture-static-source".into(),
                material_version: "version-7".into(),
                usable_until: request.deadline,
                authority_evidence: br#"{"kind":"static","adoption":"live","version":"version-7"}"#
                    .to_vec(),
            }),
            credential_headers: vec![HttpHeader {
                name: "authorization".into(),
                value: format!("Bearer {TOKEN}"),
            }],
        };
        match self.behavior {
            Behavior::EmptyCredentialMaterial => material.credential_headers.clear(),
            Behavior::WrongAudience => material.audience = "foreign-audience".into(),
            Behavior::MissingEvidence => material.evidence = None,
            Behavior::ExpiredMaterial => {
                material.evidence.as_mut().unwrap().usable_until = Some(UNIX_EPOCH.into());
            }
            _ => {}
        }
        self.selected
            .lock()
            .unwrap()
            .insert(handle, material.clone());
        Ok(Response::new(HttpCredentialResolveResponse {
            result: Some(http_credential_resolve_response::Result::Ready(material)),
        }))
    }
    async fn authorize_send(
        &self,
        request: Request<HttpCredentialAuthorizeSendRequest>,
    ) -> Result<Response<HttpCredentialAuthorizeSendResponse>, Status> {
        self.authenticate(&request)?;
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        if matches!(
            self.behavior,
            Behavior::RevokeAfterResolve
                | Behavior::DownstreamClosedDuringAuthorization
                | Behavior::NoMaterial(NoMaterial::WithdrawDuringSend | NoMaterial::ClosedPeer)
        ) {
            self.before_send.notify_one();
            self.continue_send.notified().await;
        }
        if matches!(self.behavior, Behavior::AuthorizationUnavailable) {
            return Err(Status::unavailable("fixture unavailable"));
        }
        if matches!(self.behavior, Behavior::AuthorizationTimeout) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let request = request.into_inner();
        let context = request
            .context
            .ok_or_else(|| Status::permission_denied("context"))?;
        if self
            .contexts
            .lock()
            .unwrap()
            .remove(&request.operation_handle)
            .as_ref()
            != Some(&context)
        {
            return Err(Status::permission_denied("connector context changed"));
        }
        // Compare against the selected response, not data invented from the final check.
        let no_material = self.behavior.no_material();
        let (selection, digest) = if no_material.is_some() {
            (
                SendSelection::NoMaterialRequired(true),
                // Independent SHA256("") oracle, not the supervisor's implementation.
                hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                    .unwrap(),
            )
        } else {
            let material = self
                .selected
                .lock()
                .unwrap()
                .remove(&request.operation_handle)
                .ok_or_else(|| {
                    Status::permission_denied("single-use material operation missing")
                })?;
            assert_eq!(material.request_id, context.request_id);
            (
                SendSelection::Evidence(material.evidence.unwrap()),
                openshell_supervisor_middleware::credentials::credential_headers_sha256(
                    &material.credential_headers,
                )
                .to_vec(),
            )
        };
        if request.audience != AUDIENCE
            || context.sandbox_id != SANDBOX
            || request.selection != Some(selection)
            || request.credential_headers_sha256 != digest
        {
            return Err(Status::permission_denied("operation/selection mismatch"));
        }
        if self.revoked.load(Ordering::SeqCst) {
            return Ok(Response::new(HttpCredentialAuthorizeSendResponse {
                result: Some(http_credential_authorize_send_response::Result::Refused(
                    HttpCredentialRefusal {
                        code: HttpCredentialRefusalCode::Denied as i32,
                    },
                )),
            }));
        }
        self.send_grants.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(HttpCredentialAuthorizeSendResponse {
            result: Some(http_credential_authorize_send_response::Result::Allowed(
                HttpCredentialSendPermit {
                    request_id: context.request_id,
                    operation_handle: request.operation_handle,
                    no_material_required: no_material.is_some()
                        && no_material != Some(NoMaterial::WrongSelection)
                        || matches!(self.behavior, Behavior::MaterialPermitClaimsNoMaterial),
                    credential_headers_sha256: if matches!(self.behavior, Behavior::WrongDigest) {
                        vec![0; 32]
                    } else if no_material == Some(NoMaterial::NonemptyDigest) {
                        // SHA256("abc"): a valid digest that is not the empty injection list.
                        hex::decode(
                            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                        )
                        .unwrap()
                    } else {
                        request.credential_headers_sha256
                    },
                    response_custody: vec![], // attached only by the owning duplex stream below
                    send_start_by: if matches!(self.behavior, Behavior::ExpiredPermit) {
                        Some(UNIX_EPOCH.into())
                    } else {
                        request.deadline
                    },
                },
            )),
        }))
    }
}

#[tonic::async_trait]
impl HttpInstallationExchange for Authority {
    type ExchangeStream = ReceiverStream<Result<InstallationExchangeReply, Status>>;

    async fn exchange(
        &self,
        request: Request<tonic::Streaming<InstallationExchangeRequest>>,
    ) -> Result<Response<Self::ExchangeStream>, Status> {
        let claims = self.authenticate(&request)?;
        let key = URL_SAFE_NO_PAD
            .decode(claims.exchange_key.unwrap().x)
            .unwrap();
        let metadata = request.metadata().clone();
        let mut stream = request.into_inner();
        let authority = self.clone();
        let behavior = self.behavior;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            use installation_exchange_reply::Event as Reply;
            use installation_exchange_request::Event;
            let mut challenge = [0_u8; 32];
            aws_lc_rs::rand::fill(&mut challenge).unwrap();
            let reply = |event| tx.send(Ok(InstallationExchangeReply { event: Some(event) }));
            reply(Reply::Challenge(challenge.to_vec())).await.unwrap();
            let Event::Open(open) = stream.message().await.unwrap().unwrap().event.unwrap() else {
                panic!("expected signed opening");
            };
            let transcript = [
                b"openshell-exchange-v1\0".as_slice(),
                &challenge,
                &open.resolve_request,
            ]
            .concat();
            if aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, key)
                .verify(&transcript, &open.signature)
                .is_err()
            {
                let _ = tx
                    .send(Err(Status::permission_denied("opening proof")))
                    .await;
                return;
            }
            let resolve =
                HttpCredentialResolveRequest::decode(open.resolve_request.as_slice()).unwrap();
            let mut custody = resolve.response_custody.clone();
            let resolved = authority
                .resolve(Request::from_parts(
                    metadata.clone(),
                    Default::default(),
                    resolve,
                ))
                .await;
            let resolved = match resolved {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            if reply(Reply::Resolved(resolved)).await.is_err() {
                return;
            }
            let Ok(Some(next)) = stream.message().await else {
                return;
            };
            let Event::Authorize(auth) = next.event.unwrap() else {
                panic!("expected authorization");
            };
            let authorized =
                authority.authorize_send(Request::from_parts(metadata, Default::default(), auth));
            let authorized = tokio::select! {
                biased;
                _ = stream.message() => return, // closure revokes a still-pending sender
                auth = authorized => auth,
            };
            let mut authorized = match authorized {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };
            if matches!(
                behavior,
                Behavior::LostAuthorization | Behavior::NoMaterial(NoMaterial::LostPermit)
            ) {
                return;
            }
            if matches!(
                behavior,
                Behavior::WrongCustody | Behavior::NoMaterial(NoMaterial::StaleCustody)
            ) {
                custody[0] ^= 1;
            }
            if let Some(http_credential_authorize_send_response::Result::Allowed(permit)) =
                &mut authorized.result
            {
                permit.response_custody = custody;
            }
            if reply(Reply::Authorized(authorized)).await.is_err() {
                return;
            }
            let Ok(Some(next)) = stream.message().await else {
                return;
            };
            let Event::Response(mut captured) = next.event.unwrap() else {
                panic!("expected complete response");
            };
            assert!(captured.response_complete);
            assert!(captured.headers.iter().all(|h| h.name != "authorization"));
            authority.responses.fetch_add(1, Ordering::SeqCst);
            authority
                .response_bodies
                .lock()
                .unwrap()
                .push(captured.body.clone());
            authority
                .response_trailers
                .lock()
                .unwrap()
                .push(captured.trailers.clone());
            if matches!(behavior, Behavior::ResponseTimeout) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if matches!(
                behavior,
                Behavior::ResponseBlocked
                    | Behavior::ResponseBodyUnavailable
                    | Behavior::ResponseBodyBlocked
            ) || captured
                .trailers
                .last()
                .is_some_and(|trailer| trailer.name == "x-forbidden-last")
            {
                let _ = tx
                    .send(Err(Status::permission_denied("response policy")))
                    .await;
                return;
            }
            if matches!(behavior, Behavior::MissingCompletion) {
                captured.response_complete = false;
            }
            if reply(Reply::Response(captured)).await.is_ok()
                && matches!(behavior, Behavior::FailedTerminal)
            {
                let _ = tx.send(Err(Status::unavailable("reply status"))).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct Fixture {
    policy: SandboxPolicy,
    omit_connection: bool,
    omit_guard: bool,
    asserted_proof: Option<VerifiedCredentialConnector>,
    engine: Arc<crate::opa::OpaEngine>,
    connection: crate::opa::CredentialConnection,
    authority: Authority,
    runner: ChainRunner,
    chain: Vec<ChainEntry>,
    token_slot: BearerTokenSlot,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn start(behavior: Behavior) -> Self {
        Self::start_with_payload_limit(behavior, 1024 * 1024).await
    }

    async fn start_with_payload_limit(behavior: Behavior, payload_limit: u64) -> Self {
        Self::start_for_host(behavior, payload_limit, "provider.test").await
    }

    async fn start_for_host(behavior: Behavior, payload_limit: u64, host: &str) -> Self {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let signing = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let store = ExtensionCredentialStore::new_installation().unwrap();
        let key = store.installation().unwrap().1.public_key();
        let execution = behavior.execution();
        let claims = ExtensionJwtClaims {
            exchange_key: Some(ExchangeKey {
                profile: "openshell-exchange-v1".into(),
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(if matches!(behavior, Behavior::WrongEnrollment) {
                    &[7; 32]
                } else {
                    key
                }),
            }),
            iss: "test-gateway".into(),
            aud: AUDIENCE.into(),
            sub: format!("spiffe://openshell/sandbox/{SANDBOX}"),
            iat: now,
            exp: now + 300,
            jti: uuid::Uuid::new_v4().to_string(),
            caller_kind: ExtensionCallerKind::Supervisor,
            sandbox_id: Some(SANDBOX.into()),
            instance_id: Some(INSTANCE.into()),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(EXTENSION_JWT_TYP.into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(signing.serialize_pem().as_bytes()).unwrap(),
        )
        .unwrap();
        let token_slot = store
            .install("test/authority", &token, (now + 300) * 1000, now * 1000)
            .unwrap();
        let authority = Authority {
            expected_proof: Arc::new(Mutex::new(None)),
            contexts: Arc::new(Mutex::new(HashMap::new())),
            expected_host: host.into(),
            key: DecodingKey::from_ed_pem(signing.public_key_pem().as_bytes()).unwrap(),
            behavior,
            payload_limit,
            revoked: Arc::new(AtomicBool::new(false)),
            selected: Arc::new(Mutex::new(HashMap::new())),
            resolutions: Arc::new(AtomicUsize::new(0)),
            authorizations: Arc::new(AtomicUsize::new(0)),
            access_grants: Arc::new(AtomicUsize::new(0)),
            material_reads: Arc::new(AtomicUsize::new(0)),
            send_grants: Arc::new(AtomicUsize::new(0)),
            responses: Arc::new(AtomicUsize::new(0)),
            response_bodies: Arc::new(Mutex::new(Vec::new())),
            response_trailers: Arc::new(Mutex::new(Vec::new())),
            before_send: Arc::new(Notify::new()),
            continue_send: Arc::new(Notify::new()),
        };
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let identity = Identity::from_pem(pem.as_bytes(), cert.key_pair.serialize_pem());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = authority.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(identity))
                .unwrap()
                .add_service(SupervisorMiddlewareServer::new(service.clone()))
                .add_service(
                    HttpInstallationExchangeServer::new(service)
                        .max_decoding_message_size(
                            openshell_supervisor_middleware::MIDDLEWARE_GRPC_MESSAGE_BYTES,
                        )
                        .max_encoding_message_size(
                            openshell_supervisor_middleware::MIDDLEWARE_GRPC_MESSAGE_BYTES,
                        ),
                )
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let registry = MiddlewareRegistry::connect_services_authenticated(
            vec![],
            vec![SupervisorMiddlewareService {
                name: "test/authority".into(),
                grpc_endpoint: format!("https://localhost:{}", address.port()),
                max_payload_bytes: payload_limit,
                tls_ca_cert_pem: pem.into_bytes(),
                audience: AUDIENCE.into(),
                request_timeout: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 200_000_000,
                }),
                allow_insecure_transport: false,
            }],
            &HashMap::from([("test/authority".into(), token_slot.clone())]),
        )
        .await
        .unwrap();
        let runner = ChainRunner::from_registry(registry);
        let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(connector_policy(
            host,
            behavior.no_material().is_some(),
        ))
        .unwrap();
        let pin = policy.network_middlewares["protected"].credential_connectors[0].clone();
        let mut policy = policy;
        if execution {
            let m = policy.network_middlewares.get_mut("protected").unwrap();
            m.credential_connectors.clear();
            m.execution_authority = true;
            policy
                .network_policies
                .get_mut("provider")
                .unwrap()
                .binaries
                .clear();
        }
        let engine = Arc::new(crate::opa::OpaEngine::from_proto(&policy).unwrap());
        engine.set_middleware_runner_for_tests(runner.clone());
        let connection =
            crate::proxy::credential_tests::admit_test_credential_connection(&engine, host).await;
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let expected = VerifiedCredentialConnector {
            path: pin.path.clone(),
            sha256: pin.sha256.clone(),
            policy_hash: openshell_core::policy_identity::deterministic_policy_hash(&policy),
        };
        let proof = if execution {
            VerifiedCredentialOrigin::Execution {
                policy_hash: expected.policy_hash.clone(),
            }
        } else {
            VerifiedCredentialOrigin::Connector(expected.clone())
        };
        assert_eq!(connection.proof_for(host, 443, &guard).unwrap(), proof);
        *authority.expected_proof.lock().unwrap() = Some(expected);
        Self {
            policy,
            omit_connection: false,
            omit_guard: false,
            asserted_proof: None,
            engine,
            connection,
            authority,
            runner,
            token_slot,
            server,
            chain: vec![ChainEntry {
                credential_authority: true,
                execution_authority: execution,
                name: "protected".into(),
                implementation: "test/authority".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            }],
        }
    }

    async fn exchange(&self, response: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        self.exchange_guarded(response, None).await
    }

    async fn exchange_guarded(
        &self,
        response: Vec<u8>,
        guard: Option<&crate::opa::PolicyGenerationGuard>,
    ) -> (Vec<u8>, Vec<u8>) {
        let admitted_guard = self
            .engine
            .generation_guard(self.engine.current_generation())
            .unwrap();
        let guard = if self.omit_guard {
            None
        } else {
            guard.or(Some(&admitted_guard))
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let never_ends = matches!(self.authority.behavior, Behavior::ResponseNeverEnds);
        let cert = rcgen::generate_simple_self_signed(vec!["provider.test".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let upstream_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let provider_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let no_material = self.authority.behavior.no_material();
        let provider = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(provider_config))
                .accept(stream)
                .await
                .unwrap();
            let mut received = Vec::new();
            let mut buf = [0; 4096];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if received.ends_with(br#"{"model":"fixture-model"}"#)
                    || no_material.is_some() && received.ends_with(b"\r\n\r\n")
                {
                    // Fragment actual TCP writes independently of HTTP chunks.
                    // The response parser cannot depend on read/chunk alignment.
                    let fragment_size = if response.len() < 4096 { 13 } else { 8192 };
                    for fragment in response.chunks(fragment_size) {
                        if stream.write_all(fragment).await.is_err() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    if never_ends {
                        // Keep the HTTP body open until the supervisor closes its
                        // side at the original operation deadline.
                        let _ = stream.read(&mut [0; 1]).await;
                    }
                    let _ = stream.shutdown().await;
                    break;
                }
            }
            received
        });
        let upstream = TcpStream::connect(address).await.unwrap();
        openshell_core::net::set_tcp_nodelay_best_effort(&upstream);
        let mut upstream =
            crate::l7::tls::tls_connect_upstream(upstream, "provider.test", &upstream_config)
                .await
                .unwrap();
        let (mut client, mut workload) = tokio::io::duplex(8 * 1024 * 1024);
        let private_target;
        let (method, path, body) = if no_material.is_some() {
            let path = if no_material == Some(NoMaterial::ChangedRoute) {
                "/other-read"
            } else {
                NO_MATERIAL_PATH
            };
            ("GET", path, b"".as_slice())
        } else {
            let path = if matches!(self.authority.behavior, Behavior::PrivateTargetRefusal) {
                private_target = format!("/openshell:resolve:env:{PRIVATE_CANARY}");
                private_target.as_str()
            } else {
                "/generate"
            };
            ("POST", path, br#"{"model":"fixture-model"}"#.as_slice())
        };
        let private_headers = "Proxy-Authorization: forged\r\nCookie: forged\r\nApi-Key: forged\r\nX-Api-Key: forged\r\nX-Amz-Security-Token: forged\r\nX-Example-Control: forged\r\n";
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: provider.test\r\nAuthorization: workload-intent\r\nx-openshell-execution: forged\r\n{private_headers}Content-Length: {}\r\n\r\n",
            body.len()
        );
        let req = L7Request {
            action: method.into(),
            target: path.into(),
            query_params: HashMap::new(),
            raw_header: [raw.as_bytes(), body].concat(),
            body_length: BodyLength::ContentLength(body.len() as u64),
        };
        let mut request_id = uuid::Uuid::now_v7();
        if matches!(self.authority.behavior, Behavior::ExpiredOperation) {
            let created_ms = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                - 31_000;
            let mut bytes = *request_id.as_bytes();
            bytes[..6].copy_from_slice(&created_ms.to_be_bytes()[2..]);
            request_id = uuid::Uuid::from_bytes(bytes);
        }
        let middleware = HttpResponseMiddlewareRelay {
            credential_connection: (!self.omit_connection).then_some(&self.connection),
            upstream_transport: crate::l7::tls::UpstreamTransport::AuthenticatedTls,
            chain: &self.chain,
            runner: &self.runner,
            request_context: RequestContext {
                verified_credential_connector: self.asserted_proof.clone(),
                request_id: request_id.to_string(),
                sandbox_id: SANDBOX.into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "provider.test".into(),
                port: 443,
                method: method.into(),
                path: path.into(),
                query: String::new(),
            },
            policy_name: "fixture",
            generation_guard: guard,
            whole_body_timeout: if never_ends {
                Duration::from_mins(1)
            } else {
                Duration::from_secs(2)
            },
        };
        if matches!(self.authority.behavior, Behavior::DelayedCapture) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let accepted = AcceptedResponseSink::capture(&mut client, true).unwrap();
        let relay = accepted.relay(
            &req,
            &mut upstream,
            RelayRequestOptions {
                generation_guard: guard,
                ..Default::default()
            },
            middleware,
            None,
        );
        let close = async {
            if matches!(
                self.authority.behavior,
                Behavior::DownstreamClosedDuringAuthorization
                    | Behavior::NoMaterial(NoMaterial::ClosedPeer)
            ) {
                self.authority.before_send.notified().await;
                workload.shutdown().await.unwrap();
            }
        };
        let (outcome, ()) = tokio::join!(relay, close);
        assert!(matches!(outcome.unwrap(), RelayOutcome::Consumed));
        drop(client);
        upstream.shutdown().await.unwrap();
        drop(upstream);
        let mut safe = Vec::new();
        workload.read_to_end(&mut safe).await.unwrap();
        (provider.await.unwrap(), safe)
    }
}

fn response(body: &[u8]) -> Vec<u8> {
    [format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes(), body].concat()
}

#[tokio::test]
async fn protected_send_uses_tls_authority_and_selected_material_once() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let (sent, safe) = fixture.exchange(response(br#"{"ok":true}"#)).await;
    let sent = String::from_utf8(sent).unwrap();
    assert!(sent.contains(&format!("authorization: Bearer {TOKEN}\r\n")));
    assert!(!sent.contains("workload-intent"));
    assert!(!sent.contains("forged"));
    assert!(safe.ends_with(br#"{"ok":true}"#));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.responses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn revocation_between_resolution_and_final_check_sends_zero_bytes() {
    let fixture = Fixture::start(Behavior::RevokeAfterResolve).await;
    let revoke = async {
        fixture.authority.before_send.notified().await;
        fixture.authority.revoked.store(true, Ordering::SeqCst);
        fixture.authority.continue_send.notify_one();
    };
    let ((sent, safe), ()) = tokio::join!(fixture.exchange(response(b"{}")), revoke);
    assert!(sent.is_empty());
    assert!(safe.starts_with(b"HTTP/1.1 502"));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn local_policy_reload_during_remote_final_check_sends_zero_bytes() {
    let fixture = Fixture::start(Behavior::RevokeAfterResolve).await;
    let engine = &fixture.engine;
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    let reload = async {
        fixture.authority.before_send.notified().await;
        engine
            .enter_fail_closed("fixture policy withdrawn")
            .unwrap();
        fixture.authority.continue_send.notify_one();
    };
    let ((sent, safe), ()) = tokio::join!(
        fixture.exchange_guarded(response(b"{}"), Some(&guard)),
        reload
    );
    assert!(sent.is_empty());
    assert!(safe.starts_with(b"HTTP/1.1 502"));
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    assert!(
        fixture.authority.selected.lock().unwrap().is_empty(),
        "authority allowed its one send, but local guard must still refuse"
    );
}

#[tokio::test]
async fn malformed_unavailable_expired_and_timed_out_authority_never_send() {
    for behavior in [
        Behavior::WrongBinding,
        Behavior::WrongAudience,
        Behavior::MissingEvidence,
        Behavior::EmptyCredentialMaterial,
        Behavior::MaterialPermitClaimsNoMaterial,
        Behavior::ExpiredMaterial,
        Behavior::WrongDigest,
        Behavior::ExpiredPermit,
        Behavior::ResolutionUnavailable,
        Behavior::AuthorizationUnavailable,
        Behavior::AuthorizationTimeout,
        Behavior::WrongCustody,
        Behavior::LostAuthorization,
        Behavior::DownstreamClosedDuringAuthorization,
    ] {
        let fixture = Fixture::start(behavior).await;
        let (sent, safe) = fixture.exchange(response(b"{}")).await;
        assert!(sent.is_empty());
        assert!(safe.starts_with(b"HTTP/1.1 502"));
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn concurrent_operations_each_resolve_and_authorize_without_material_cache() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let (first, second) = tokio::join!(
        fixture.exchange(response(b"{}")),
        fixture.exchange(response(b"{}"))
    );
    assert!(!first.0.is_empty() && !second.0.is_empty());
    assert!(first.1.ends_with(b"{}") && second.1.ends_with(b"{}"));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 2);
    assert!(fixture.authority.selected.lock().unwrap().is_empty());
}

#[tokio::test]
async fn protected_response_policy_and_literal_echo_block_after_single_send() {
    for (behavior, body) in [
        (Behavior::ResponseBlocked, b"provider-output".as_slice()),
        (Behavior::Allow, TOKEN.as_bytes()),
    ] {
        let fixture = Fixture::start(behavior).await;
        let (sent, safe) = fixture.exchange(response(body)).await;
        assert!(!sent.is_empty());
        assert!(!safe.windows(body.len()).any(|w| w == body));
        assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn missing_rotated_transport_credential_cannot_fall_back() {
    let fixture = Fixture::start(Behavior::Allow).await;
    fixture.token_slot.clear();
    let (sent, safe) = fixture.exchange(response(b"{}")).await;
    assert!(sent.is_empty());
    assert!(safe.starts_with(b"HTTP/1.1 502"));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn protected_response_strips_credential_headers_and_interim_fields() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let wire = format!(
        "HTTP/1.1 103 Early Hints\r\nX-Echo: {TOKEN}\r\n\r\nHTTP/1.1 200 OK\r\nAuthorization: Bearer {TOKEN}\r\nX-Api-Key: {TOKEN}\r\nSet-Cookie: credential={TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    let (sent, safe) = fixture.exchange(wire.into_bytes()).await;
    assert!(!sent.is_empty());
    assert!(safe.starts_with(b"HTTP/1.1 200"));
    assert!(safe.ends_with(b"{}"));
    assert!(!safe.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    assert!(
        !String::from_utf8(safe)
            .unwrap()
            .to_ascii_lowercase()
            .contains("set-cookie")
    );
}

#[tokio::test]
async fn partial_compressed_streaming_and_chunked_secret_responses_never_escape() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let split = TOKEN.len() / 2;
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n{:X}\r\n{}\r\n0\r\n\r\n",
        split,
        &TOKEN[..split],
        TOKEN.len() - split,
        &TOKEN[split..]
    );
    let trailers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: x-echo\r\nConnection: close\r\n\r\n2\r\n{{}}\r\n0\r\nx-echo: {TOKEN}\r\n\r\n"
    );
    for wire in [
        format!("HTTP/1.1 200 OK\r\nX-Echo: {TOKEN}"),
        chunked,
        trailers,
        format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{TOKEN}",
            TOKEN.len()
        ),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{TOKEN}",
            TOKEN.len()
        ),
    ] {
        let (sent, safe) = fixture.exchange(wire.into_bytes()).await;
        assert!(!sent.is_empty());
        assert!(safe.starts_with(b"HTTP/1.1 502"));
        assert!(!safe.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    }
}

#[tokio::test]
async fn ambiguous_fail_open_and_missing_authority_never_fall_back() {
    for mode in 0..3 {
        let mut fixture = Fixture::start(Behavior::Allow).await;
        match mode {
            0 => fixture.chain.push(fixture.chain[0].clone()),
            1 => fixture.chain[0].on_error = OnError::FailOpen,
            _ => fixture.chain[0].implementation = "missing/authority".into(),
        }
        let (sent, safe) = fixture.exchange(response(b"{}")).await;
        assert!(sent.is_empty());
        assert!(safe.starts_with(b"HTTP/1.1 502"));
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn protected_request_preflight_allows_https_only_without_ordinary_request_binding() {
    use crate::l7::middleware::{
        MiddlewareApplyResult, apply_middleware_chain_for_scheme_with_request_id,
    };
    use openshell_supervisor_middleware::TransformedBodyPolicy;

    let fixture = Fixture::start(Behavior::Allow).await;
    let engine = crate::opa::OpaEngine::from_strings(
        include_str!("../../../data/sandbox-policy.rego"),
        include_str!("../../../testdata/sandbox-policy.yaml"),
    )
    .unwrap();
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    let ctx = crate::l7::relay::L7EvalContext {
        host: "provider.test".into(),
        port: 443,
        upstream_transport: crate::l7::tls::UpstreamTransport::AuthenticatedTls,
        ..Default::default()
    };
    for (scheme, upgrade, allowed) in [
        ("https", "", true),
        ("http", "", false),
        (
            "https",
            "Connection: Upgrade\r\nUpgrade: websocket\r\n",
            false,
        ),
        ("https", "Connection: Upgrade\r\nUpgrade: h2c\r\n", false),
    ] {
        let req = L7Request {
            action: "GET".into(),
            target: "/generate".into(),
            query_params: HashMap::new(),
            raw_header: format!("GET /generate HTTP/1.1\r\nHost: provider.test\r\n{upgrade}\r\n")
                .into_bytes(),
            body_length: BodyLength::None,
        };
        let result = apply_middleware_chain_for_scheme_with_request_id(
            req,
            &mut tokio::io::empty(),
            &ctx,
            scheme,
            fixture.chain.clone(),
            &fixture.runner,
            &guard,
            TransformedBodyPolicy::NotPolicyRelevant,
            "preflight-operation",
        )
        .await
        .unwrap();
        assert_eq!(matches!(result, MiddlewareApplyResult::Allowed(_)), allowed);
    }
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 0);
}

// Provider-wire construction is independent of the production chunk decoder.
fn sse_wire(body: &[u8], width: usize, ending: &[u8]) -> Vec<u8> {
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for chunk in body.chunks(width) {
        wire.extend_from_slice(format!("{:x};fixture=yes\r\n", chunk.len()).as_bytes());
        wire.extend_from_slice(chunk);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(ending);
    wire
}

#[tokio::test]
async fn finite_sse_chunked_wire_is_whole_body_validated_and_matches_independent_oracle() {
    // Exact expected event bytes are an oracle, not output of the implementation
    // decoder. HTTP chunk and TCP fragmentation split UTF-8 and event delimiters.
    let expected = "event: response.output_text.delta\ndata: {\"delta\":\"héllo\"}\n\nevent: response.completed\ndata: {\"ok\":true}\n\n".as_bytes();
    let fixture = Fixture::start(Behavior::Allow).await;
    for width in [1, 7, 37] {
        let (sent, safe) = fixture
            .exchange(sse_wire(expected, width, b"0\r\n\r\n"))
            .await;
        assert_eq!(
            sent.windows(TOKEN.len())
                .filter(|w| *w == TOKEN.as_bytes())
                .count(),
            1
        );
        assert!(safe.starts_with(b"HTTP/1.1 200 OK\r\n"));
        // Whole-body response policy normally emits Content-Length. Compare the
        // actual delivered body directly to the independent complete SSE oracle.
        let header_end = safe.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&safe[header_end..], expected);
        assert!(
            std::str::from_utf8(&safe[..header_end])
                .unwrap()
                .contains("Content-Length:")
        );
        assert_eq!(
            fixture
                .authority
                .response_bodies
                .lock()
                .unwrap()
                .last()
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn sse_split_material_trailers_and_incomplete_wire_never_deliver_partial_events() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let sensitive = format!("data: {{\"text\":\"{TOKEN}\"}}\n\n");
    let safe_event = b"data: {\"visible\":\"must-not-leak-on-failure\"}\n\n";
    let cases = [
        sse_wire(sensitive.as_bytes(), 2, b"0\r\n\r\n"),
        sse_wire(
            safe_event,
            3,
            format!("0\r\nx-leak: {TOKEN}\r\n\r\n").as_bytes(),
        ),
        sse_wire(safe_event, 5, b"0\r\nAuthorization: forbidden\r\n\r\n"),
        sse_wire(safe_event, 7, b"3\r\nx"),
        sse_wire(safe_event, 9, b"invalid-chunk\r\n"),
    ];
    for wire in cases {
        let (sent, delivered) = fixture.exchange(wire).await;
        assert!(!sent.is_empty());
        assert!(delivered.starts_with(b"HTTP/1.1 502"));
        assert!(!delivered.windows(5).any(|w| w == b"data:"));
        assert!(
            !delivered
                .windows(TOKEN.len())
                .any(|w| w == TOKEN.as_bytes())
        );
    }
}

#[tokio::test]
async fn sse_authority_cannot_downgrade_inspection_or_release_on_error() {
    let body = b"data: {\"text\":\"must-not-leak-on-failure\"}\n\n";
    for behavior in [
        Behavior::MissingCompletion,
        Behavior::FailedTerminal,
        Behavior::ResponseBodyBlocked,
        Behavior::ResponseBodyUnavailable,
        Behavior::ResponseTimeout,
    ] {
        let fixture = Fixture::start(behavior).await;
        let (sent, delivered) = fixture.exchange(sse_wire(body, 3, b"0\r\n\r\n")).await;
        assert!(!sent.is_empty());
        assert!(delivered.starts_with(b"HTTP/1.1 502") || delivered.starts_with(b"HTTP/1.1 403"));
        assert!(!delivered.windows(5).any(|w| w == b"data:"));
        assert!(
            !delivered
                .windows(b"must-not-leak-on-failure".len())
                .any(|w| w == b"must-not-leak-on-failure")
        );
    }
}

#[tokio::test]
async fn nonterminating_sse_is_cut_off_by_original_operation_deadline_without_partial_leak() {
    let fixture = Fixture::start(Behavior::ResponseNeverEnds).await;
    let wire = sse_wire(b"data: {\"text\":\"not-complete\"}\n\n", 8, b"");
    let started = tokio::time::Instant::now();
    let (sent, delivered) = tokio::time::timeout(Duration::from_secs(35), fixture.exchange(wire))
        .await
        .expect("original 30-second deadline must bound response and cleanup");
    assert!(started.elapsed() >= Duration::from_secs(29));
    assert!(!sent.is_empty());
    assert!(delivered.is_empty() || delivered.starts_with(b"HTTP/1.1 502"));
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    assert!(fixture.authority.response_bodies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sse_over_binding_capacity_never_releases_buffered_prefix() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let mut body = b"data: ".to_vec();
    body.extend(std::iter::repeat_n(b'x', 1024 * 1024 + 1));
    body.extend_from_slice(b"\n\n");
    let (sent, delivered) = fixture.exchange(sse_wire(&body, 8192, b"0\r\n\r\n")).await;
    assert!(!sent.is_empty());
    assert!(delivered.starts_with(b"HTTP/1.1 502"));
    assert!(!delivered.windows(5).any(|w| w == b"data:"));
    assert!(fixture.authority.response_bodies.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sse_staged_response_limit_includes_headers_after_complete_policy_evaluation() {
    let fixture = Fixture::start_with_payload_limit(Behavior::Allow, 4 * 1024 * 1024).await;
    let mut body = b"data: ".to_vec();
    body.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024 - 8));
    body.extend_from_slice(b"\n\n");
    assert_eq!(body.len(), 4 * 1024 * 1024);
    let (sent, delivered) = fixture.exchange(sse_wire(&body, 8192, b"0\r\n\r\n")).await;
    assert!(!sent.is_empty());
    assert!(delivered.starts_with(b"HTTP/1.1 502"));
    assert!(!delivered.windows(5).any(|w| w == b"data:"));
    assert_eq!(
        fixture.authority.response_bodies.lock().unwrap().as_slice(),
        &[body]
    );
}

#[tokio::test]
async fn delayed_capture_preserves_uuid_creation_deadline_on_real_wire() {
    let fixture = Fixture::start(Behavior::DelayedCapture).await;
    let body = b"data: {\"ok\":true}\n\n";
    let (sent, delivered) = fixture.exchange(sse_wire(body, 3, b"0\r\n\r\n")).await;
    assert!(!sent.is_empty());
    assert!(delivered.starts_with(b"HTTP/1.1 200 OK"));
    // Authority::resolve independently verifies the serialized deadline against
    // timestamp bytes; now()+30 seconds after the delay would fail that oracle.
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn expired_uuid_operation_never_resolves_or_dispatches() {
    let fixture = Fixture::start(Behavior::ExpiredOperation).await;
    let (sent, _) = fixture
        .exchange(sse_wire(b"data: {}\n\n", 3, b"0\r\n\r\n"))
        .await;
    assert!(sent.is_empty());
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn protected_status_lines_reject_malformed_grammar_and_controls_before_policy() {
    let fixture = Fixture::start(Behavior::Allow).await;
    for status_line in [
        "HTTP/2 200 OK",
        "HTTP/1.1 20 OK",
        "HTTP/1.1 2000 OK",
        "HTTP/1.1 099 OK",
        "HTTP/1.1 +200 OK",
        "HTTP/1.1  200 OK",
        "HTTP/1.1\t200 OK",
        "HTTP/1.1 200",
        "HTTP/1.1 200 bad\treason",
        "HTTP/1.1 200 bad\0reason",
        "HTTP/1.1 200 bad\u{7f}reason",
        "HTTP/1.1 200 bad\u{85}reason",
        "HTTP/1.1 200 bad\nreason",
        "HTTP/1.1 200 bad\rreason",
        "HTTP/1.1 103 bad\treason\r\n\r\nHTTP/1.1 200 OK",
    ] {
        let wire = format!("{status_line}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
        let (sent, safe) = fixture.exchange(wire.into_bytes()).await;
        assert!(sent.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
        assert_eq!(
            safe, b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "status line {status_line:?}"
        );
        assert_eq!(
            fixture.authority.responses.load(Ordering::SeqCst),
            0,
            "reject malformed status before response policy"
        );
    }
}

#[tokio::test]
async fn protected_status_preserves_valid_version_and_code_with_local_reason_only() {
    let fixture = Fixture::start(Behavior::Allow).await;
    for (wire_status, expected) in [
        ("HTTP/1.0 200 Provider custom", "HTTP/1.0 200 OK\r\n"),
        ("HTTP/1.1 201 ", "HTTP/1.1 201 Created\r\n"),
        ("HTTP/1.1 599 Provider custom", "HTTP/1.1 599 \r\n"),
    ] {
        let wire = format!(
            "{wire_status}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        let (_, safe) = fixture.exchange(wire.into_bytes()).await;
        assert!(
            safe.starts_with(expected.as_bytes()),
            "expected {expected:?}"
        );
        assert!(safe.ends_with(b"{}"));
        assert!(!String::from_utf8_lossy(&safe).contains("Provider custom"));
    }
    assert_eq!(fixture.authority.responses.load(Ordering::SeqCst), 3);
}

fn connector_policy(host: &str, no_material: bool) -> SandboxPolicy {
    use sha2::{Digest, Sha256};
    static PIN: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    let (path, sha256) = PIN.get_or_init(|| {
        let path = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let sha256 = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
        (serde_json::to_string(&path).unwrap(), sha256)
    });
    let (method, route) = if no_material {
        ("GET", NO_MATERIAL_PATH)
    } else {
        ("POST", "/generate")
    };
    openshell_policy::parse_sandbox_policy(&format!(
        "version: 1\nnetwork_middlewares:\n  protected:\n    middleware: test/authority\n    credential_authority: true\n    credential_connectors:\n      - path: {path}\n        sha256: {sha256}\n    on_error: fail_closed\n    endpoints:\n      include: [\"{host}\"]\nnetwork_policies:\n  provider:\n    name: provider\n    endpoints:\n      - host: \"{host}\"\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        rules:\n          - allow: {{ method: {method}, path: {route} }}\n    binaries:\n      - path: {path}\n"
    )).unwrap()
}

#[tokio::test]
async fn missing_or_crossed_connector_context_is_refused_before_resolve() {
    for variant in 0..5 {
        let mut fixture = Fixture::start(Behavior::Allow).await;
        if variant == 0 {
            fixture.omit_connection = true;
        } else if variant == 1 {
            fixture.omit_guard = true;
        } else {
            let mut proof = fixture
                .authority
                .expected_proof
                .lock()
                .unwrap()
                .clone()
                .unwrap();
            match variant {
                2 => proof.path = "/different/client".into(),
                3 => proof.sha256 = "b".repeat(64),
                _ => proof.policy_hash = "c".repeat(64),
            }
            fixture.asserted_proof = Some(proof);
        }
        let (sent, safe) = fixture.exchange(response(b"{}")).await;
        assert!(sent.is_empty());
        assert!(safe.starts_with(b"HTTP/1.1 502"));
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 0);
    }
    let first = Fixture::start(Behavior::Allow).await;
    let second = Fixture::start(Behavior::Allow).await;
    let foreign = second
        .engine
        .generation_guard(second.engine.current_generation())
        .unwrap();
    let (sent, _) = first
        .exchange_guarded(response(b"{}"), Some(&foreign))
        .await;
    assert!(sent.is_empty());
    assert_eq!(first.authority.resolutions.load(Ordering::SeqCst), 0);
    let stale = first
        .engine
        .generation_guard(first.engine.current_generation())
        .unwrap();
    first
        .engine
        .enter_fail_closed("fixture withdrawal")
        .unwrap();
    let (sent, _) = first.exchange_guarded(response(b"{}"), Some(&stale)).await;
    assert!(sent.is_empty());
    assert_eq!(first.authority.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn old_or_optional_connector_capability_never_resolves_or_sends() {
    for behavior in [
        Behavior::OldConnector,
        Behavior::OptionalConnector,
        Behavior::OldCustodyProfile,
        Behavior::OptionalCustodyProfile,
    ] {
        let fixture = Fixture::start(behavior).await;
        let (sent, _) = fixture.exchange(response(b"{}")).await;
        assert!(sent.is_empty());
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 0);
        let guard = fixture
            .engine
            .generation_guard(fixture.engine.current_generation())
            .unwrap();
        assert!(fixture.engine.enforced_capabilities(&guard).await.is_err());
    }
}

#[tokio::test]
async fn valid_bearer_but_different_enrollment_cannot_resolve_or_send() {
    let fixture = Fixture::start(Behavior::WrongEnrollment).await;
    let (sent, safe) = fixture.exchange(response(b"must not escape")).await;
    assert!(sent.is_empty());
    assert!(safe.starts_with(b"HTTP/1.1 502"));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn whole_execution_policy_withholds_entire_response_through_forbidden_last_trailer() {
    // Both selection arms, same origin response except exactly one forbidden final trailer.
    // The independent authority observations distinguish a parser failure from policy denial.
    let body = b"origin body unique to this test";
    for behavior in [
        Behavior::ExecutionAllow,
        Behavior::NoMaterial(NoMaterial::Allow),
    ] {
        let fixture = Fixture::start(behavior).await;
        let (positive_origin, delivered) = fixture.exchange(sse_wire(body, 3, b"0\r\n\r\n")).await;
        if behavior.no_material().is_some() {
            let expected = format!(
                "GET {NO_MATERIAL_PATH} HTTP/1.1\r\nHost: provider.test\r\nContent-Length: 0\r\n\r\n"
            );
            assert_eq!(positive_origin, expected.as_bytes());
        } else {
            assert_eq!(
                positive_origin
                    .windows(TOKEN.len())
                    .filter(|s| *s == TOKEN.as_bytes())
                    .count(),
                1
            );
        }
        assert!(delivered.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let header_end = delivered.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            &delivered[header_end..],
            body,
            "zero trailers: complete origin content released"
        );

        let (negative_origin, withheld) = fixture
            .exchange(sse_wire(body, 3, b"0\r\nx-forbidden-last: denied\r\n\r\n"))
            .await;
        assert_eq!(
            negative_origin, positive_origin,
            "same complete single request reached origin"
        );
        assert_eq!(
            withheld, REFUSED_RESPONSE,
            "one forbidden final trailer: zero origin bytes released"
        );
        let a = &fixture.authority;
        assert_eq!(a.send_grants.load(Ordering::SeqCst), 2);
        assert_eq!(
            &*a.response_bodies.lock().unwrap(),
            &[body.as_slice(), body.as_slice()]
        );
        assert_eq!(
            &*a.response_trailers.lock().unwrap(),
            &[
                vec![],
                vec![HttpHeader {
                    name: "x-forbidden-last".into(),
                    value: "denied".into()
                }]
            ],
            "actual complete-response policy input: zero versus one forbidden trailer"
        );
        let expected_reads = if behavior.no_material().is_some() {
            0
        } else {
            2
        };
        assert_eq!(a.material_reads.load(Ordering::SeqCst), expected_reads);
    }
}

#[tokio::test]
async fn no_material_cannot_dispatch_with_bad_selection_digest_custody_route_or_lost_permit() {
    use NoMaterial::*;
    for (case, expected_send_grants) in [
        (MissingHandle, 0),
        (ChangedRoute, 0),
        (NarrowProfile, 0),
        (ClosedPeer, 0),
        (WrongSelection, 1),
        (NonemptyDigest, 1),
        (StaleCustody, 1),
        (LostPermit, 1),
    ] {
        let fixture = Fixture::start(Behavior::NoMaterial(case)).await;
        let (origin, received) = fixture.exchange(response(b"must not be read")).await;
        assert_eq!(origin, b"", "{case:?}: origin received HTTP bytes");
        assert_eq!(received, REFUSED_RESPONSE, "{case:?}");
        assert_eq!(
            fixture.authority.material_reads.load(Ordering::SeqCst),
            0,
            "{case:?}"
        );
        assert_eq!(
            fixture.authority.send_grants.load(Ordering::SeqCst),
            expected_send_grants,
            "{case:?}: test exercised the intended gate"
        );
    }
}

#[tokio::test]
async fn no_material_withdrawal_between_access_and_send_grants_prevents_dispatch() {
    let fixture = Fixture::start(Behavior::NoMaterial(NoMaterial::WithdrawDuringSend)).await;
    let a = &fixture.authority;
    let revoke = async {
        a.before_send.notified().await;
        a.revoked.store(true, Ordering::SeqCst);
        a.continue_send.notify_one();
    };
    let ((origin, received), ()) = tokio::join!(fixture.exchange(response(b"never read")), revoke);
    assert!(origin.is_empty());
    assert_eq!(received, REFUSED_RESPONSE);
    assert_eq!(
        (
            a.access_grants.load(Ordering::SeqCst),
            a.material_reads.load(Ordering::SeqCst),
            a.authorizations.load(Ordering::SeqCst),
            a.send_grants.load(Ordering::SeqCst)
        ),
        (1, 0, 1, 0)
    );
}

#[tokio::test]
async fn no_material_missing_or_optional_capability_cannot_claim_loaded_enforcement() {
    for case in [NoMaterial::OldCapability, NoMaterial::OptionalCapability] {
        let fixture = Fixture::start(Behavior::NoMaterial(case)).await;
        let (origin, received) = fixture.exchange(response(b"never read")).await;
        assert!(origin.is_empty());
        assert_eq!(received, REFUSED_RESPONSE);
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
        let guard = fixture
            .engine
            .generation_guard(fixture.engine.current_generation())
            .unwrap();
        assert!(fixture.engine.enforced_capabilities(&guard).await.is_err());
    }
}

#[tokio::test]
async fn protected_private_target_reference_absent_from_emitted_refusal_event() {
    use openshell_ocsf::OcsfJsonlLayer;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;

    let fixture = Fixture::start(Behavior::PrivateTargetRefusal).await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry().with(OcsfJsonlLayer::new(capture.clone()));
    let (origin, received) = fixture
        .exchange(response(b"never read"))
        .with_subscriber(subscriber)
        .await;
    assert!(origin.is_empty());
    assert_eq!(received, REFUSED_RESPONSE);

    let actual = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!actual.contains(PRIVATE_CANARY));
    let event = actual
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|e| e["message"] == "Protected HTTP exchange refused before dispatch")
        .expect("the actual emitted refusal event");
    assert_eq!(event["http_request"]["url"]["hostname"], "provider.test");
    assert!(event["http_request"]["url"].get("path").is_none());
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn protected_no_material_success_events_identify_the_selected_operation_and_release() {
    use tracing::instrument::WithSubscriber;
    let fixture = Fixture::start(Behavior::NoMaterial(NoMaterial::Allow)).await;
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer({
            let capture = capture.clone();
            move || capture.clone()
        })
        .finish();
    let (origin, received) = fixture
        .exchange(response(b"approved read"))
        .with_subscriber(subscriber)
        .await;
    assert_eq!(
        origin,
        format!(
            "GET {NO_MATERIAL_PATH} HTTP/1.1\r\nHost: provider.test\r\nContent-Length: 0\r\n\r\n"
        )
        .as_bytes()
    );
    assert!(received.ends_with(b"approved read"));

    let actual = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let transitions = actual
        .lines()
        .filter_map(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            let fields = &event["fields"];
            Some((
                fields["response_custody_event"].as_str()?.to_owned(),
                fields["request_id"].as_str()?.to_owned(),
            ))
        })
        .collect::<Vec<_>>();
    let id = &transitions[0].1;
    assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 7);
    assert_eq!(
        transitions
            .iter()
            .map(|(label, id)| (label.as_str(), id.as_str()))
            .collect::<Vec<_>>(),
        [
            "resolve_no_material_accepted",
            "permit_no_material_accepted",
            "response_released"
        ]
        .map(|label| (label, id.as_str()))
    );
}
