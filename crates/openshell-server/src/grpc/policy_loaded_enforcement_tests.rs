// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Actual installed OPA/registry producer to gateway persistence/query consumer.
use super::tests::{test_sandbox, with_sandbox};
use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, external_http_exchange_capabilities,
};
use openshell_core::proto::*;
use openshell_extension_core::{BearerTokenSlot, ExtensionCredentialStore};
use openshell_supervisor_middleware::MiddlewareRegistry;
use openshell_supervisor_network::opa::OpaEngine;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};

const SANDBOX: &str = "00000000-0000-4000-8000-000000000001";
const NAME: &str = "receipt-sandbox";
const SERVICE: &str = "receipt/authority";

#[derive(Clone)]
struct ManifestService {
    upgraded: Arc<AtomicBool>,
    signed_identity: Arc<std::sync::Mutex<Option<jsonwebtoken::DecodingKey>>>,
}

impl ManifestService {
    fn authenticate(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let authorization = metadata.get("authorization").and_then(|v| v.to_str().ok());
        if authorization != Some("Bearer receipt-test-token") {
            let identity = self.signed_identity.lock().unwrap();
            let key = identity
                .as_ref()
                .ok_or_else(|| Status::unauthenticated("missing fixture authentication"))?;
            let token = authorization
                .and_then(|value| value.strip_prefix("Bearer "))
                .ok_or_else(|| Status::unauthenticated("missing bearer"))?;
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
            validation.set_audience(&["urn:receipt-test"]);
            validation.set_issuer(&["openshell-gateway:receipt-gateway"]);
            let verified = jsonwebtoken::decode::<openshell_extension_core::ExtensionJwtClaims>(
                token,
                key,
                &validation,
            )
            .map_err(|_| Status::unauthenticated("invalid fixture signature"))?;
            use openshell_extension_core::ExtensionCallerKind;
            let claims = verified.claims;
            let expected_identity = claims.caller_kind == ExtensionCallerKind::Gateway
                && claims.sub == claims.iss
                && claims.sandbox_id.is_none()
                && claims.instance_id.is_none()
                && claims.exchange_key.is_none();
            if verified.header.typ.as_deref() != Some(openshell_extension_core::EXTENSION_JWT_TYP)
                || !expected_identity
            {
                return Err(Status::unauthenticated("unexpected fixture identity"));
            }
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl supervisor_middleware_server::SupervisorMiddleware for ManifestService {
    type EvaluateWebSocketSessionStream =
        ReceiverStream<Result<WebSocketSessionEventResult, Status>>;
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        self.authenticate(request.metadata())?;
        let upgraded = self.upgraded.load(Ordering::SeqCst);
        let capabilities = if upgraded {
            external_http_exchange_capabilities()
                .iter()
                .copied()
                .map(str::to_string)
                .collect()
        } else {
            vec![]
        };
        let bindings = vec![MiddlewareBinding {
            operation: SupervisorMiddlewareOperation::HttpExchange.into(),
            phase: SupervisorMiddlewarePhase::PreCredentials.into(),
            max_payload_bytes: 4 * 1024 * 1024,
            ..Default::default()
        }];
        let mut metadata = extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            SERVICE,
            "1",
            capabilities.clone(),
        );
        metadata.required_capabilities.extend(capabilities);
        Ok(Response::new(MiddlewareManifest {
            name: SERVICE.into(),
            service_version: "fixture".into(),
            expected_audience: "urn:receipt-test".into(),
            extension: Some(metadata),
            bindings,
        }))
    }
    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.authenticate(request.metadata())?;
        let request = request.into_inner();
        assert_eq!(request.middleware_name, SERVICE);
        let valid = request.config.unwrap().fields.is_empty();
        Ok(Response::new(ValidateConfigResponse {
            valid,
            reason: String::new(),
        }))
    }
    async fn evaluate_http_request(
        &self,
        _: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        Err(Status::unimplemented(
            "receipt test never sends business requests",
        ))
    }
    async fn evaluate_web_socket_session(
        &self,
        _: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented("no websocket binding"))
    }
}

struct ManifestFixture {
    service: ManifestService,
    registration: SupervisorMiddlewareService,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for ManifestFixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl ManifestFixture {
    async fn start() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = certificate.cert.pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let service = ManifestService {
            upgraded: Arc::new(AtomicBool::new(false)),
            signed_identity: Arc::new(std::sync::Mutex::new(None)),
        };
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                    certificate.cert.pem(),
                    certificate.key_pair.serialize_pem(),
                )))
                .unwrap()
                .add_service(
                    supervisor_middleware_server::SupervisorMiddlewareServer::new(server_service),
                )
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        Self {
            service,
            server,
            registration: SupervisorMiddlewareService {
                name: SERVICE.into(),
                grpc_endpoint: format!("https://localhost:{port}"),
                tls_ca_cert_pem: pem.into_bytes(),
                audience: "urn:receipt-test".into(),
                max_payload_bytes: 4 * 1024 * 1024,
                ..Default::default()
            },
        }
    }
    async fn registry(&self) -> MiddlewareRegistry {
        self.registry_with_credential(
            BearerTokenSlot::new("receipt-test-token", current_time_ms() + 300_000).unwrap(),
        )
        .await
    }
    async fn registry_with_credential(&self, credential: BearerTokenSlot) -> MiddlewareRegistry {
        MiddlewareRegistry::connect_services_authenticated(
            vec![],
            vec![self.registration.clone()],
            &HashMap::from([(SERVICE.into(), credential)]),
        )
        .await
        .unwrap()
    }
}

/// Exercise the exact credential constructor and admission boundary used by `CreateSandbox`.
/// The gateway owns a control-plane bearer, never the future supervisor's installation key.
#[tokio::test]
async fn gateway_admits_protected_policy_without_claiming_installation_possession() {
    let fixture = ManifestFixture::start().await;
    let reg = &fixture.registration;
    let signing = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
    let key = jsonwebtoken::DecodingKey::from_ed_pem(signing.public_key_pem.as_bytes()).unwrap();
    *fixture.service.signed_identity.lock().unwrap() = Some(key);
    let issuer = crate::auth::sandbox_jwt::ExtensionJwtIssuer::from_pem(
        signing.signing_key_pem.as_bytes(),
        signing.public_key_pem.as_bytes(),
        signing.kid,
        "receipt-gateway",
        std::time::Duration::from_mins(15),
    )
    .unwrap();
    let gateway = crate::mint_gateway_extension_credential(
        &Arc::new(issuer),
        crate::ExtensionKind::Middleware,
        &reg.name,
        &reg.audience,
        &reg.grpc_endpoint,
        reg.allow_insecure_transport,
    )
    .unwrap()
    .unwrap();
    assert!(gateway.slot.installation_key().is_none());
    let old_registry = fixture.registry_with_credential(gateway.slot.clone()).await;
    fixture.service.upgraded.store(true, Ordering::SeqCst);
    let registry = fixture.registry_with_credential(gateway.slot.clone()).await;

    let policy = exchange_policy();
    let admission = crate::middleware::validate_policy;
    admission(&registry, &policy).await.expect("admission must validate the registered service, not demand the supervisor's installation key");

    // The same registry cannot substantiate installed enforcement or even open a protected
    // exchange (this authenticated service deliberately exposes no installation RPC).
    let engine = OpaEngine::from_proto(&policy).unwrap();
    engine
        .replace_middleware_registry(registry.clone())
        .unwrap();
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    let error = engine.enforced_capabilities(&guard).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires local installation possession"),
        "{error}"
    );

    let error = admission(&old_registry, &policy).await.unwrap_err();
    assert!(
        error.message().contains("capability is unavailable"),
        "{error}"
    );
}

fn exchange_policy() -> SandboxPolicy {
    let mut policy = openshell_policy::restrictive_default_policy();
    policy.network_middlewares.insert(
        "protected".into(),
        NetworkMiddlewareConfig {
            middleware: SERVICE.into(),
            external_http_exchange: true,
            on_error: "fail_closed".into(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec!["provider.test".into()],
                exclude: vec![],
            }),
            ..Default::default()
        },
    );
    openshell_policy::validate_and_canonicalize_sandbox_policy(policy).unwrap()
}

fn report(admission: SandboxConfigurationAdmission) -> Request<ReportSandboxConfigurationRequest> {
    with_sandbox(
        Request::new(ReportSandboxConfigurationRequest {
            sandbox_id: SANDBOX.into(),
            admission: Some(admission),
            ..Default::default()
        }),
        SANDBOX,
    )
}

async fn config(state: &Arc<ServerState>) -> GetSandboxConfigResponse {
    handle_get_sandbox_config(
        state,
        with_sandbox(
            Request::new(GetSandboxConfigRequest {
                name: NAME.into(),
                workspace_scope: Some(workspace_selector("default")),
                supported_enforcement_capabilities: external_http_exchange_capabilities()
                    .iter()
                    .map(|v| (*v).to_string())
                    .collect(),
            }),
            SANDBOX,
        ),
    )
    .await
    .unwrap()
    .into_inner()
}
async fn status(state: &Arc<ServerState>) -> GetSandboxPolicyStatusResponse {
    handle_get_sandbox_policy_status(
        state,
        authed_request(GetSandboxPolicyStatusRequest {
            sandbox: NAME.into(),
            workspace_scope: Some(workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
}
async fn assert_no_evidence(state: &Arc<ServerState>) {
    let response = status(state).await;
    assert!(response.loaded_enforcement.is_none());
}
async fn policy_status(state: &Arc<ServerState>, version: u32, result: PolicyStatus) {
    handle_report_policy_status(
        state,
        with_sandbox(
            Request::new(ReportPolicyStatusRequest {
                sandbox_id: SANDBOX.into(),
                version,
                status: result.into(),
                load_error: String::new(),
            }),
            SANDBOX,
        ),
    )
    .await
    .unwrap();
}
fn acceptance(instance: &str, config: &GetSandboxConfigResponse) -> SandboxConfigurationAdmission {
    SandboxConfigurationAdmission {
        instance_id: instance.into(),
        state: ConfigurationAdmissionState::Accepted.into(),
        policy_version: config.version,
        policy_hash: config.policy_hash.clone(),
        config_revision: config.config_revision,
        provider_env_revision: config.provider_env_revision,
        ..Default::default()
    }
}

#[tokio::test]
async fn installed_exchange_evidence_is_exact_current_and_gateway_keyed() {
    use crate::grpc::provider_readiness::tests::register_session;
    let fixture = ManifestFixture::start().await;
    let old_registry = fixture.registry().await;
    fixture.service.upgraded.store(true, Ordering::SeqCst);
    let installation = ExtensionCredentialStore::new_installation().unwrap();
    let (instance, key) = installation.installation().unwrap();
    let registry = fixture
        .registry_with_credential(
            installation
                .install(
                    SERVICE,
                    "receipt-test-token",
                    current_time_ms() + 300_000,
                    current_time_ms(),
                )
                .unwrap(),
        )
        .await;
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state).unwrap().middleware_registry = Arc::new(registry.clone());
    let policy = exchange_policy();
    state
        .store
        .put_message(&test_sandbox(SANDBOX, NAME, policy.clone(), vec![]))
        .await
        .unwrap();
    handle_report_sandbox_configuration(
        &state,
        report(SandboxConfigurationAdmission {
            instance_id: instance.into(),
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let withheld = handle_get_sandbox_config(
        &state,
        with_sandbox(
            Request::new(GetSandboxConfigRequest {
                name: NAME.into(),
                ..Default::default()
            }),
            SANDBOX,
        ),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(!withheld.configuration_admitted);
    assert!(withheld.policy.is_none());
    assert!(withheld.supervisor_middleware_services.is_empty());
    let current = config(&state).await;
    assert!(current.configuration_admitted);
    let mut accepted = acceptance(instance, &current);
    policy_status(&state, current.version, PolicyStatus::Loaded).await;
    assert_no_evidence(&state).await;
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );

    // An old cached manifest cannot prove installation, even after the service upgrades.
    let engine = OpaEngine::from_proto(current.policy.as_ref().unwrap()).unwrap();
    engine.replace_middleware_registry(old_registry).unwrap();
    let old_guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&old_guard, SANDBOX, &accepted)
            .await
            .is_err()
    );
    let guard = engine
        .reload_policy_and_middleware_from_proto_with_pid(
            current.policy.as_ref().unwrap(),
            0,
            registry,
        )
        .unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&old_guard, SANDBOX, &accepted)
            .await
            .is_err()
    );
    let mut wrong_policy = accepted.clone();
    wrong_policy.policy_hash = "different-policy".into();
    assert!(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &wrong_policy)
            .await
            .is_err()
    );
    accepted.loaded_enforcement = Some(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &accepted)
            .await
            .unwrap(),
    );
    assert_eq!(
        accepted
            .loaded_enforcement
            .as_ref()
            .unwrap()
            .enforced_capabilities,
        external_http_exchange_capabilities()
    );
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    // Installed evidence without current key enrollment remains withheld.
    assert_no_evidence(&state).await;
    let hello = SupervisorHello {
        sandbox_id: SANDBOX.into(),
        instance_id: instance.into(),
        exchange_public_key: key.public_key().to_vec(),
        ..Default::default()
    };
    register_session(&state.supervisor_sessions, &hello).unwrap();
    let evidence = status(&state).await.loaded_enforcement.unwrap();
    let mut expected = accepted.loaded_enforcement.clone().unwrap();
    expected.registered_exchange_public_key = key.public_key().to_vec();
    assert_eq!(evidence, expected);
    // A caller cannot smuggle a registration key through a status report.
    let mut forged = accepted.clone();
    forged.loaded_enforcement = Some(expected);
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(forged))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        handle_report_sandbox_configuration(
            &state,
            authed_request(report(accepted.clone()).into_inner())
        )
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );

    for field in 0..8 {
        let mut bad = accepted.clone();
        let evidence = bad.loaded_enforcement.as_mut().unwrap();
        match field {
            0 => evidence.sandbox_id = "other".into(),
            1 => evidence.instance_id = uuid::Uuid::new_v4().to_string(),
            2 => evidence.policy_version += 1,
            3 => evidence.policy_hash = "other".into(),
            4 => evidence.config_revision = evidence.config_revision.wrapping_add(1),
            5 => evidence.provider_env_revision = evidence.provider_env_revision.wrapping_add(1),
            6 => evidence.enforced_capabilities.clear(),
            _ => evidence.enforced_capabilities.push("unknown".into()),
        }
        assert!(
            handle_report_sandbox_configuration(&state, report(bad))
                .await
                .is_err()
        );
    }
    let mut replacement = hello.clone();
    replacement.instance_id = uuid::Uuid::new_v4().to_string();
    register_session(&state.supervisor_sessions, &replacement).unwrap();
    assert_no_evidence(&state).await;
    register_session(&state.supervisor_sessions, &hello).unwrap();
    assert!(status(&state).await.loaded_enforcement.is_some());
    state.supervisor_sessions.disconnect(SANDBOX);
    assert_no_evidence(&state).await;
    register_session(&state.supervisor_sessions, &hello).unwrap();

    policy_status(&state, current.version, PolicyStatus::Failed).await;
    assert_no_evidence(&state).await;
    policy_status(&state, current.version, PolicyStatus::Loaded).await;
    assert_no_evidence(&state).await;
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    engine.enter_fail_closed("failed installation").unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &accepted)
            .await
            .is_err()
    );

    let mut changed = policy;
    changed.network_middlewares.clear();
    state
        .store
        .put_policy_revision(
            "receipt-v2",
            SANDBOX,
            "default",
            2,
            &changed.encode_to_vec(),
            &deterministic_policy_hash(&changed),
        )
        .await
        .unwrap();
    assert_no_evidence(&state).await;
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
}

#[test]
fn loaded_evidence_requires_exact_typed_source_and_effective_policy() {
    let policy = openshell_policy::restrictive_default_policy();
    let revision = SandboxPolicyRevision {
        version: 1,
        policy_hash: deterministic_policy_hash(&policy),
        policy: Some(policy.clone()),
        ..Default::default()
    };
    let mut config = GetSandboxConfigResponse {
        version: 1,
        policy_hash: revision.policy_hash.clone(),
        policy: Some(policy),
        ..Default::default()
    };
    assert!(exact_loaded_policy(&revision, &config));
    config.policy.as_mut().unwrap().network_policies.insert(
        "provider".into(),
        NetworkPolicyRule {
            name: "provider".into(),
            ..Default::default()
        },
    );
    assert!(!exact_loaded_policy(&revision, &config));
    config.policy_hash = deterministic_policy_hash(config.policy.as_ref().unwrap());
    assert!(!exact_loaded_policy(&revision, &config));
}

#[tokio::test]
async fn stock_admission_remains_supported_without_an_exchange_key() {
    let state = test_server_state().await;
    state
        .store
        .put_message(&test_sandbox(
            SANDBOX,
            NAME,
            openshell_policy::restrictive_default_policy(),
            vec![],
        ))
        .await
        .unwrap();
    let instance = uuid::Uuid::new_v4().to_string();
    handle_report_sandbox_configuration(
        &state,
        report(SandboxConfigurationAdmission {
            instance_id: instance.clone(),
            state: ConfigurationAdmissionState::Pending.into(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let current = config(&state).await;
    let mut accepted = acceptance(&instance, &current);
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    policy_status(&state, current.version, PolicyStatus::Loaded).await;
    assert_no_evidence(&state).await;
    let engine = OpaEngine::from_proto(current.policy.as_ref().unwrap()).unwrap();
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    accepted.loaded_enforcement = Some(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &accepted)
            .await
            .unwrap(),
    );
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    let evidence = status(&state).await.loaded_enforcement.unwrap();
    assert!(evidence.enforced_capabilities.is_empty());
    assert!(evidence.registered_exchange_public_key.is_empty());
    assert_eq!(Some(evidence), accepted.loaded_enforcement);
}
