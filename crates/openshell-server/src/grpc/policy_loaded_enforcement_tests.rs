// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Actual installed OPA/registry producer to gateway persistence/query consumer.
use super::tests::{test_sandbox, with_sandbox};
use super::*;
use crate::grpc::test_support::{authed_request, test_server_state};
use openshell_core::extension_protocol::{
    ExtensionFamily, HTTP_CREDENTIAL_ACCESS_CAPABILITY, HTTP_CREDENTIAL_REQUIRED_CAPABILITIES,
    extension_metadata,
};
use openshell_core::proto::*;
use openshell_extension_core::{BearerTokenSlot, ExtensionCredentialStore};
use openshell_supervisor_middleware::MiddlewareRegistry;
use openshell_supervisor_network::opa::OpaEngine;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};

const SANDBOX: &str = "receipt-sandbox-id";
const NAME: &str = "receipt-sandbox";
const SERVICE: &str = "receipt/authority";

#[derive(Clone)]
struct ManifestService {
    execution_authority: bool,
    upgraded: Arc<AtomicBool>,
    describes: Arc<AtomicUsize>,
    signed_identity: Arc<std::sync::Mutex<Option<(jsonwebtoken::DecodingKey, Option<String>)>>>,
}

impl ManifestService {
    fn authenticate(&self, metadata: &tonic::metadata::MetadataMap) -> Result<(), Status> {
        let authorization = metadata.get("authorization").and_then(|v| v.to_str().ok());
        if authorization != Some("Bearer receipt-test-token") {
            let identity = self.signed_identity.lock().unwrap();
            let (key, expected_instance) = identity
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
            let expected_identity = if let Some(instance) = expected_instance {
                claims.caller_kind == ExtensionCallerKind::Supervisor
                    && claims.sandbox_id.as_deref() == Some(SANDBOX)
                    && claims.instance_id.as_ref() == Some(instance)
            } else {
                claims.caller_kind == ExtensionCallerKind::Gateway
                    && claims.sub == claims.iss
                    && claims.sandbox_id.is_none()
                    && claims.instance_id.is_none()
                    && claims.exchange_key.is_none()
            };
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
        self.describes.fetch_add(1, Ordering::SeqCst);
        let upgraded = self.upgraded.load(Ordering::SeqCst);
        let capabilities = if upgraded {
            openshell_core::extension_protocol::credential_enforcement_profile(
                self.execution_authority,
            )
            .iter()
            .copied()
            .map(str::to_string)
            .collect()
        } else {
            vec![]
        };
        let mut bindings = vec![MiddlewareBinding {
            operation: SupervisorMiddlewareOperation::HttpResponse.into(),
            phase: SupervisorMiddlewarePhase::PreReturn.into(),
            max_payload_bytes: 4 * 1024 * 1024,
            ..Default::default()
        }];
        if upgraded {
            bindings.push(MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpCredentials.into(),
                phase: SupervisorMiddlewarePhase::PreCredentials.into(),
                max_payload_bytes: 4 * 1024 * 1024,
                ..Default::default()
            });
        }
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
            reason: if valid {
                ""
            } else {
                "unexpected fixture config"
            }
            .into(),
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
        Self::start_with_profile(false).await
    }
    async fn start_with_profile(execution_authority: bool) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = certificate.cert.pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let service = ManifestService {
            execution_authority,
            upgraded: Arc::new(AtomicBool::new(false)),
            describes: Arc::new(AtomicUsize::new(0)),
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
    for execution_authority in [false, true] {
        gateway_admission_without_installation_possession(execution_authority).await;
    }
}

async fn gateway_admission_without_installation_possession(execution_authority: bool) {
    let fixture = ManifestFixture::start_with_profile(execution_authority).await;
    let reg = &fixture.registration;
    let signing = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
    let key = jsonwebtoken::DecodingKey::from_ed_pem(signing.public_key_pem.as_bytes()).unwrap();
    *fixture.service.signed_identity.lock().unwrap() = Some((key, None));
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

    let mut policy = openshell_policy::restrictive_default_policy();
    policy.network_middlewares.insert(
        "protected".into(),
        NetworkMiddlewareConfig {
            middleware: SERVICE.into(),
            credential_authority: true,
            execution_authority,
            credential_connectors: if execution_authority {
                vec![]
            } else {
                vec![CredentialConnector {
                    path: "/usr/bin/curl".into(),
                    sha256: "a".repeat(64),
                }]
            },
            on_error: "fail_closed".into(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec!["provider.test".into()],
                exclude: vec![],
            }),
            ..Default::default()
        },
    );
    let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(policy).unwrap();
    let mut policy = policy;
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
    policy
        .network_middlewares
        .get_mut("protected")
        .unwrap()
        .config = Some(prost_types::Struct {
        fields: [("unknown".into(), Default::default())].into(),
    });
    let error = admission(&registry, &policy).await.unwrap_err();
    assert!(
        error.message().contains("unexpected fixture config"),
        "{error}"
    );

    // Neither opting out of authentication nor a registration bound to the wrong audience works.
    for (insecure, audience, failure) in [
        (true, reg.audience.as_str(), "Describe failed"),
        (false, "urn:wrong-audience", "expects audience"),
    ] {
        let result = MiddlewareRegistry::connect_services_authenticated(
            vec![],
            vec![SupervisorMiddlewareService {
                allow_insecure_transport: insecure,
                audience: audience.into(),
                ..reg.clone()
            }],
            &HashMap::from([(reg.name.clone(), gateway.slot.clone())]),
        )
        .await;
        let error = result.err().expect("registration must fail");
        assert!(error.to_string().contains(failure), "{error}");
    }
}

fn report(admission: SandboxConfigurationAdmission) -> Request<ReportSandboxConfigurationRequest> {
    // Exercise the genuine protobuf envelope, including optional evidence.
    let wire = ReportSandboxConfigurationRequest {
        sandbox_id: SANDBOX.into(),
        admission: Some(admission),
        ..Default::default()
    }
    .encode_to_vec();
    with_sandbox(
        Request::new(ReportSandboxConfigurationRequest::decode(wire.as_slice()).unwrap()),
        SANDBOX,
    )
}
async fn instance_request(
    state: &Arc<ServerState>,
    instance: &str,
) -> Request<RefreshSandboxTokenRequest> {
    let sandbox = state
        .store
        .get_message::<Sandbox>(SANDBOX)
        .await
        .unwrap()
        .unwrap();
    let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::read(
        &sandbox.metadata.unwrap().annotations,
    )
    .unwrap();
    let auth = state
        .sandbox_session_jwt_authority
        .as_ref()
        .unwrap()
        .mint_persisted_launch(SANDBOX, &identity)
        .unwrap();
    let mut request = with_sandbox(
        Request::new(RefreshSandboxTokenRequest {
            extension_service_names: vec![SERVICE.into()],
            configuration_instance_id: instance.into(),
        }),
        SANDBOX,
    );
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", auth.supervisor.gateway_token.expose_secret())
            .parse()
            .unwrap(),
    );
    request
}

async fn refresh_instance(
    state: &Arc<ServerState>,
    instance: &str,
) -> Result<RefreshSandboxTokenResponse, Status> {
    crate::grpc::auth_rpc::handle_refresh_sandbox_token(
        state,
        instance_request(state, instance).await,
    )
    .await
    .map(Response::into_inner)
}

async fn config(state: &Arc<ServerState>) -> GetSandboxConfigResponse {
    handle_get_sandbox_config(
        state,
        with_sandbox(
            Request::new(GetSandboxConfigRequest {
                name: NAME.into(),
                workspace_scope: Some(workspace_selector("default")),
                supported_enforcement_capabilities: HTTP_CREDENTIAL_REQUIRED_CAPABILITIES
                    .map(str::to_string)
                    .to_vec(),
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
async fn assert_no_loaded_observation(state: &Arc<ServerState>) {
    let response = status(state).await;
    assert!(response.loaded_enforcement.is_none());
    assert!(response.loaded_policy_observation.is_none());
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

fn observation_fixture(
    source: &SandboxPolicy,
    effective: &SandboxPolicy,
) -> (
    SandboxPolicyRevision,
    GetSandboxConfigResponse,
    SandboxConfigurationAdmission,
) {
    let revision = SandboxPolicyRevision {
        version: 1,
        policy_hash: deterministic_policy_hash(source),
        policy: Some(source.clone()),
        status: PolicyStatus::Loaded.into(),
        ..Default::default()
    };
    let config = GetSandboxConfigResponse {
        version: 1,
        policy_hash: deterministic_policy_hash(effective),
        policy: Some(effective.clone()),
        policy_source: PolicySource::Sandbox.into(),
        configuration_admitted: true,
        config_revision: 2,
        provider_env_revision: 3,
        ..Default::default()
    };
    let mut admission = acceptance("00000000-0000-4000-8000-000000000001", &config);
    // Synthetic evidence isolates the consumer's derivation proof. The test
    // below separately exercises the actual installed enforcement producer.
    admission.loaded_enforcement = Some(LoadedEnforcementEvidence {
        sandbox_id: SANDBOX.into(),
        instance_id: admission.instance_id.clone(),
        policy_version: admission.policy_version,
        policy_hash: admission.policy_hash.clone(),
        config_revision: admission.config_revision,
        provider_env_revision: admission.provider_env_revision,
        enforced_capabilities: vec![],
    });
    (revision, config, admission)
}

#[test]
fn loaded_policy_observation_binds_distinct_source_and_effective_hashes() {
    let source = openshell_policy::restrictive_default_policy();
    let sandbox = test_sandbox(SANDBOX, NAME, source.clone(), vec!["bound-provider".into()]);
    let rule_name = openshell_policy::provider_rule_name("bound-provider");
    let mut effective = source.clone();
    effective.network_policies.insert(
        rule_name.clone(),
        NetworkPolicyRule {
            name: rule_name.clone(),
            ..Default::default()
        },
    );
    let (revision, config, admission) = observation_fixture(&source, &effective);
    assert_ne!(revision.policy_hash, admission.policy_hash);
    let observation =
        loaded_policy_observation_v1(&sandbox, &revision, &admission, &config).unwrap();
    assert_eq!(observation.source_policy_hash, revision.policy_hash);
    assert_eq!(observation.effective_policy.as_ref(), Some(&effective));
    assert_eq!(observation.enforcement, admission.loaded_enforcement);
    assert_eq!(observation.inert_provider_rule, rule_name);
    assert_eq!(
        LoadedPolicyObservationV1::decode(observation.encode_to_vec().as_slice()).unwrap(),
        observation
    );

    let (identity_revision, identity_config, identity_admission) =
        observation_fixture(&source, &source);
    let identity = loaded_policy_observation_v1(
        &sandbox,
        &identity_revision,
        &identity_admission,
        &identity_config,
    )
    .unwrap();
    assert!(identity.inert_provider_rule.is_empty());
    assert_eq!(identity.source_policy_hash, identity_admission.policy_hash);

    let mut stale_source = revision.clone();
    stale_source.policy_hash.clone_from(&admission.policy_hash);
    assert!(loaded_policy_observation_v1(&sandbox, &stale_source, &admission, &config).is_none());

    // Even mutually matching generation claims cannot substitute a source hash
    // (or any other hash) for the canonical effective policy identity.
    let mut bad_config = config.clone();
    let mut bad_admission = admission.clone();
    bad_config.policy_hash.clone_from(&revision.policy_hash);
    bad_admission.policy_hash.clone_from(&revision.policy_hash);
    bad_admission
        .loaded_enforcement
        .as_mut()
        .unwrap()
        .policy_hash = revision.policy_hash.clone();
    assert!(
        loaded_policy_observation_v1(&sandbox, &revision, &bad_admission, &bad_config).is_none()
    );
    let mut global = config.clone();
    global.policy_source = PolicySource::Global.into();
    assert!(loaded_policy_observation_v1(&sandbox, &revision, &admission, &global).is_none());
    for providers in [
        vec![],
        vec!["other".into()],
        vec!["bound-provider".into(); 2],
    ] {
        let mut wrong_binding = sandbox.clone();
        wrong_binding.spec.as_mut().unwrap().providers = providers;
        assert!(
            loaded_policy_observation_v1(&wrong_binding, &revision, &admission, &config).is_none()
        );
    }
}

#[test]
fn loaded_policy_observation_refuses_hidden_widening_with_valid_effective_hashes() {
    let mut source = openshell_policy::restrictive_default_policy();
    source.landlock.as_mut().unwrap().compatibility = "hard_requirement".into();
    source.process = Some(ProcessPolicy {
        run_as_user: "sandbox".into(),
        run_as_group: "sandbox".into(),
    });
    let sandbox = test_sandbox(SANDBOX, NAME, source.clone(), vec!["bound-provider".into()]);
    let rule_name = openshell_policy::provider_rule_name("bound-provider");
    let inert_rule = NetworkPolicyRule {
        name: rule_name.clone(),
        ..Default::default()
    };
    for mutation in 0..8 {
        let mut effective = source.clone();
        effective
            .network_policies
            .insert(rule_name.clone(), inert_rule.clone());
        let extra = effective.network_policies.get_mut(&rule_name).unwrap();
        match mutation {
            0 => extra.endpoints.push(NetworkEndpoint {
                host: "extra.example".into(),
                ports: vec![443],
                ..Default::default()
            }),
            1 => extra.binaries.push(NetworkBinary {
                path: "/usr/bin/extra".into(),
                ..Default::default()
            }),
            2 => extra.name.clear(),
            3 => {
                let other = openshell_policy::provider_rule_name("other");
                effective.network_policies.insert(
                    other.clone(),
                    NetworkPolicyRule {
                        name: other,
                        ..Default::default()
                    },
                );
            }
            4 => effective
                .filesystem
                .as_mut()
                .unwrap()
                .read_write
                .push("/extra".into()),
            5 => effective.process.as_mut().unwrap().run_as_user = "root".into(),
            6 => effective.landlock.as_mut().unwrap().compatibility = "best_effort".into(),
            _ => {
                effective.network_middlewares.insert(
                    "hidden".into(),
                    NetworkMiddlewareConfig {
                        name: "hidden".into(),
                        on_error: "fail_open".into(),
                        ..Default::default()
                    },
                );
            }
        }
        let (revision, config, admission) = observation_fixture(&source, &effective);
        assert!(validate_loaded_enforcement(SANDBOX, &admission, &config).is_ok());
        assert!(
            loaded_policy_observation_v1(&sandbox, &revision, &admission, &config).is_none(),
            "hidden derivation {mutation} must not produce an observation"
        );
    }
}

#[tokio::test]
async fn loaded_enforcement_actual_producer_cached_manifest_and_gateway_invalidation() {
    actual_producer_cached_manifest_and_gateway_invalidation(false).await;
}

#[tokio::test]
async fn loaded_policy_observation_actual_producer_with_inert_provider() {
    actual_producer_cached_manifest_and_gateway_invalidation(true).await;
}

#[tokio::test]
async fn identical_global_override_preserves_only_legacy_loaded_enforcement() {
    let state = test_server_state().await;
    let policy = openshell_policy::restrictive_default_policy();
    state
        .store
        .put_message(&test_sandbox(SANDBOX, NAME, policy, vec![]))
        .await
        .unwrap();
    let source = config(&state).await;
    policy_status(&state, source.version, PolicyStatus::Loaded).await;
    let policy = source.policy.as_ref().unwrap();
    save_global_settings(
        state.store.as_ref(),
        &StoredSettings {
            revision: 1,
            settings: BTreeMap::from([(
                POLICY_SETTING_KEY.into(),
                StoredSettingValue::Bytes(hex::encode(policy.encode_to_vec())),
            )]),
            ..Default::default()
        },
    )
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
    assert_eq!(current.policy_source, i32::from(PolicySource::Global));
    assert_eq!(current.policy_hash, source.policy_hash);
    let mut accepted = acceptance(&instance, &current);
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
    let response = status(&state).await;
    assert!(response.loaded_enforcement.is_some());
    assert_eq!(response.loaded_enforcement, accepted.loaded_enforcement);
    assert!(response.loaded_policy_observation.is_none());
}

async fn actual_producer_cached_manifest_and_gateway_invalidation(inert_provider: bool) {
    let fixture = ManifestFixture::start().await;
    let old_registry = fixture.registry().await;
    assert_eq!(fixture.service.describes.load(Ordering::SeqCst), 1);
    fixture.service.upgraded.store(true, Ordering::SeqCst);
    let mut registry = fixture.registry().await;
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state).unwrap().middleware_registry = Arc::new(registry.clone());
    let signing = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
    let issuer = crate::auth::sandbox_jwt::ExtensionJwtIssuer::from_pem(
        signing.signing_key_pem.as_bytes(),
        signing.public_key_pem.as_bytes(),
        signing.kid.clone(),
        "receipt-gateway",
        std::time::Duration::from_mins(15),
    )
    .unwrap();
    let authority = crate::auth::sandbox_jwt::SandboxSessionJwtAuthority::from_pem(
        signing.signing_key_pem.as_bytes(),
        signing.public_key_pem.as_bytes(),
        signing.kid,
        "receipt-gateway",
        Some(std::time::Duration::from_hours(1)),
    )
    .unwrap();
    Arc::get_mut(&mut state).unwrap().extension_jwt_issuer = Some(Arc::new(issuer));
    Arc::get_mut(&mut state)
        .unwrap()
        .sandbox_session_jwt_authority = Some(Arc::new(authority));

    let mut policy = openshell_policy::restrictive_default_policy();
    policy.network_middlewares.insert(
        "protected".into(),
        NetworkMiddlewareConfig {
            middleware: SERVICE.into(),
            credential_authority: true,
            execution_authority: false,
            credential_connectors: vec![CredentialConnector {
                path: "/usr/bin/curl".into(),
                sha256: "a".repeat(64),
            }],
            on_error: "fail_closed".into(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec!["provider.test".into()],
                exclude: vec![],
            }),
            ..Default::default()
        },
    );
    let mut sandbox = test_sandbox(SANDBOX, NAME, policy.clone(), vec![]);
    if inert_provider {
        let mut metadata = sandbox.metadata.clone().unwrap();
        metadata.id = "receipt-provider-id".into();
        metadata.name = "bound-provider".into();
        state
            .store
            .put_message(&Provider {
                metadata: Some(metadata.clone()),
                r#type: "receipt-empty-profile".into(),
                profile_workspace: "default".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        metadata.id = "receipt-profile-id".into();
        metadata.name = "receipt-empty-profile".into();
        state
            .store
            .put_message(&StoredProviderProfile {
                metadata: Some(metadata),
                profile: Some(ProviderProfile {
                    id: "receipt-empty-profile".into(),
                    display_name: "Receipt empty profile".into(),
                    category: ProviderProfileCategory::Other.into(),
                    ..Default::default()
                }),
            })
            .await
            .unwrap();
        sandbox.spec.as_mut().unwrap().providers = vec!["bound-provider".into()];
    }
    let identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new().unwrap();
    identity.write(&mut sandbox.metadata.as_mut().unwrap().annotations);
    state.store.put_message(&sandbox).await.unwrap();
    // A real supervisor owns possession before its Pending registration and discovery token.
    let installation = ExtensionCredentialStore::new_installation().unwrap();
    let instance = installation.installation().unwrap().0.to_string();
    assert_eq!(
        refresh_instance(&state, &instance)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
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
    // A fresh Pending registration can mint its own signed extension identity
    // before Describe/install; missing and stale old-client identities cannot.
    for requested in [String::new(), uuid::Uuid::new_v4().to_string()] {
        assert_eq!(
            refresh_instance(&state, &requested)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }
    let mint_request = instance_request(&state, &instance).await;
    let predecessor = mint_request
        .metadata()
        .get("authorization")
        .unwrap()
        .clone();
    let mint_body = mint_request.get_ref().clone();
    let minted = crate::grpc::auth_rpc::handle_refresh_sandbox_token(&state, mint_request)
        .await
        .unwrap()
        .into_inner();
    let mut retry = with_sandbox(Request::new(mint_body.clone()), SANDBOX);
    retry
        .metadata_mut()
        .insert("authorization", predecessor.clone());
    let replayed = crate::grpc::auth_rpc::handle_refresh_sandbox_token(&state, retry)
        .await
        .unwrap()
        .into_inner();
    assert!(replayed.extension_credentials[0].token == minted.extension_credentials[0].token);
    let mut changed_retry = with_sandbox(
        Request::new(RefreshSandboxTokenRequest {
            configuration_instance_id: uuid::Uuid::new_v4().to_string(),
            ..mint_body
        }),
        SANDBOX,
    );
    changed_retry
        .metadata_mut()
        .insert("authorization", predecessor);
    assert_eq!(
        crate::grpc::auth_rpc::handle_refresh_sandbox_token(&state, changed_retry)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let key = jsonwebtoken::DecodingKey::from_ed_pem(signing.public_key_pem.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["urn:receipt-test"]);
    validation.set_issuer(&["openshell-gateway:receipt-gateway"]);
    let signed = jsonwebtoken::decode::<openshell_extension_core::ExtensionJwtClaims>(
        &minted.extension_credentials[0].token,
        &key,
        &validation,
    )
    .unwrap();
    assert_eq!(
        signed.claims.instance_id.as_deref(),
        Some(instance.as_str())
    );
    assert_eq!(signed.claims.sandbox_id.as_deref(), Some(SANDBOX));
    *fixture.service.signed_identity.lock().unwrap() = Some((key.clone(), Some(instance.clone())));
    // The actual supervisor registry producer now negotiates over TLS with the
    // gateway-minted, service-verified registered-instance JWT.
    // Discovery predates the enrolled hello. Possession comes from local installation custody,
    // never from a copied discovery bearer. This test performs no credential access or origin send.
    assert!(signed.claims.exchange_key.is_none());
    let slot = installation
        .install(
            SERVICE,
            &minted.extension_credentials[0].token,
            signed.claims.exp * 1000,
            current_time_ms(),
        )
        .unwrap();
    registry = fixture.registry_with_credential(slot).await;

    // Old generated clients omit field 4. No protected policy or service
    // registrations may reach their cached parser/registry on startup or poll.
    for capabilities in [
        vec![],
        vec!["unknown-capability".to_string()],
        vec![HTTP_CREDENTIAL_ACCESS_CAPABILITY.to_string()],
    ] {
        let withheld = handle_get_sandbox_config(
            &state,
            with_sandbox(
                Request::new(GetSandboxConfigRequest {
                    name: NAME.into(),
                    workspace_scope: None,
                    supported_enforcement_capabilities: capabilities,
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
        assert!(!withheld.configuration_error.is_empty());
        assert_eq!(withheld.configuration_instance_id, instance);
        assert_eq!(withheld.policy_validation_failure_mode, "fail_closed");
        // The real gateway accepts the old supervisor's rejection tuple, so
        // startup can wait for repair without falling back to a local policy.
        let mut rejected = acceptance(&instance, &withheld);
        rejected.state = ConfigurationAdmissionState::Rejected.into();
        handle_report_sandbox_configuration(&state, report(rejected))
            .await
            .unwrap();
    }
    // Inspection by an authorized operator does not claim implementation support.
    let inspected = handle_get_sandbox_config(
        &state,
        authed_request(GetSandboxConfigRequest {
            name: NAME.into(),
            workspace_scope: Some(workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(inspected.policy.is_some());
    let current = config(&state).await;
    let mut accepted = acceptance(&instance, &current);
    // Baseline old generated protobuf ignores additive field 7. A cached old
    // registry plus LOADED/ACCEPTED still supplies no enforcement evidence.
    #[derive(Clone, PartialEq, prost::Message)]
    struct OldConfig {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(string, tag = "2")]
        middleware: String,
        #[prost(message, optional, tag = "3")]
        config: Option<prost_types::Struct>,
        #[prost(string, tag = "4")]
        on_error: String,
        #[prost(message, optional, tag = "5")]
        endpoints: Option<MiddlewareEndpointSelector>,
        #[prost(int32, tag = "6")]
        order: i32,
    }
    // The previous credential-aware peer knew field 7 but not connector pins.
    // It cannot install protected policy under the new contract either.
    let mut pre_connector_policy = current.policy.clone().unwrap();
    pre_connector_policy
        .network_middlewares
        .get_mut("protected")
        .unwrap()
        .credential_connectors
        .clear();
    assert!(OpaEngine::from_proto(&pre_connector_policy).is_err());
    let new_config = policy.network_middlewares.get("protected").unwrap();
    let old = OldConfig::decode(new_config.encode_to_vec().as_slice()).unwrap();
    let decoded_old = NetworkMiddlewareConfig::decode(old.encode_to_vec().as_slice()).unwrap();
    assert!(!decoded_old.credential_authority);
    let mut old_policy = current.policy.clone().unwrap();
    old_policy
        .network_middlewares
        .insert("protected".into(), decoded_old);
    let engine = OpaEngine::from_proto(&old_policy).unwrap();
    engine.replace_middleware_registry(old_registry).unwrap();
    let old_guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    let unrelated_engine = OpaEngine::from_proto(&old_policy).unwrap();
    let unrelated_guard = unrelated_engine
        .generation_guard(unrelated_engine.current_generation())
        .unwrap();
    assert!(
        engine
            .enforced_capabilities(&unrelated_guard)
            .await
            .is_err()
    );
    assert!(
        engine
            .enforced_capabilities(&old_guard)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    policy_status(&state, current.version, PolicyStatus::Loaded).await;
    assert_no_loaded_observation(&state).await;

    // Even a new parser cannot qualify the unchanged cached old manifest.
    let guard = engine
        .reload_from_proto_with_pid(current.policy.as_ref().unwrap(), 0)
        .unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &accepted)
            .await
            .is_err()
    );
    assert_eq!(
        fixture.service.describes.load(Ordering::SeqCst),
        3,
        "cached manifest must stay cached"
    );

    // A genuine guarded installation with the capability must still refuse an
    // accepted admission for a different policy, even when both are legitimate.
    let mut wider_policy = current.policy.clone().unwrap();
    wider_policy.network_policies.insert(
        "extra-destination".into(),
        NetworkPolicyRule {
            name: "extra-destination".into(),
            endpoints: vec![NetworkEndpoint {
                host: "extra.example".into(),
                ports: vec![443],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".into(),
            }],
        },
    );
    let wider_policy =
        openshell_policy::validate_and_canonicalize_sandbox_policy(wider_policy).unwrap();
    let wider_engine = OpaEngine::from_proto(&wider_policy).unwrap();
    wider_engine
        .replace_middleware_registry(registry.clone())
        .unwrap();
    let wider_guard = wider_engine
        .generation_guard(wider_engine.current_generation())
        .unwrap();
    assert_eq!(
        wider_engine
            .enforced_capabilities(&wider_guard)
            .await
            .unwrap(),
        HTTP_CREDENTIAL_REQUIRED_CAPABILITIES
    );
    assert_ne!(
        deterministic_policy_hash(&wider_policy),
        accepted.policy_hash
    );
    let error = wider_engine
        .loaded_enforcement_evidence(&wider_guard, SANDBOX, &accepted)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("installed policy hash"));
    let mut wider_admission = accepted.clone();
    wider_admission.policy_hash = deterministic_policy_hash(&wider_policy);
    assert_eq!(
        wider_engine
            .loaded_enforcement_evidence(&wider_guard, SANDBOX, &wider_admission)
            .await
            .unwrap()
            .policy_hash,
        wider_admission.policy_hash
    );
    let replacement_guard = wider_engine
        .reload_from_proto_with_pid(current.policy.as_ref().unwrap(), 0)
        .unwrap();
    assert!(
        wider_engine
            .loaded_enforcement_evidence(&wider_guard, SANDBOX, &wider_admission)
            .await
            .is_err()
    );
    assert_eq!(
        wider_engine
            .loaded_enforcement_evidence(&replacement_guard, SANDBOX, &accepted)
            .await
            .unwrap()
            .policy_hash,
        accepted.policy_hash
    );

    let guard = engine
        .reload_policy_and_middleware_from_proto_with_pid(
            current.policy.as_ref().unwrap(),
            0,
            registry,
        )
        .unwrap();
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
        HTTP_CREDENTIAL_REQUIRED_CAPABILITIES
    );
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    let response = status(&state).await;
    let observation = response.loaded_policy_observation.unwrap();
    let source = response.revision.unwrap();
    assert_eq!(observation.source_policy_hash, source.policy_hash);
    assert_eq!(observation.effective_policy, current.policy);
    assert_eq!(observation.enforcement, accepted.loaded_enforcement);
    if inert_provider {
        assert!(response.loaded_enforcement.is_none());
        assert_ne!(source.policy_hash, accepted.policy_hash);
        assert_eq!(
            observation.inert_provider_rule,
            openshell_policy::provider_rule_name("bound-provider")
        );
    } else {
        assert_eq!(response.loaded_enforcement, accepted.loaded_enforcement);
        assert_eq!(source.policy_hash, accepted.policy_hash);
        assert!(observation.inert_provider_rule.is_empty());
    }

    let evidence = accepted.loaded_enforcement.as_ref().unwrap();
    println!(
        "SUPPLIER_RECEIPT_VECTOR {}",
        serde_json::json!({
            "qualification": "synthetic component fixture, not installed evidence",
            "protobuf_hex": hex::encode(evidence.encode_to_vec()),
            "receipt": {
                "sandbox_id": evidence.sandbox_id, "instance_id": evidence.instance_id,
                "policy_version": evidence.policy_version, "policy_hash": evidence.policy_hash,
                "config_revision": evidence.config_revision.to_string(),
                "provider_env_revision": evidence.provider_env_revision.to_string(),
                "enforced_capabilities": evidence.enforced_capabilities,
            },
            "verified_extension_claims": signed.claims,
        })
    );

    // The current observation is idempotent, not a one-use authorization.
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    for capabilities in [
        Vec::new(),
        vec!["unknown-capability".to_string()],
        vec![HTTP_CREDENTIAL_ACCESS_CAPABILITY.to_string()],
        HTTP_CREDENTIAL_REQUIRED_CAPABILITIES
            .into_iter()
            .rev()
            .map(str::to_string)
            .collect(),
    ] {
        let mut bad = accepted.clone();
        bad.loaded_enforcement
            .as_mut()
            .unwrap()
            .enforced_capabilities = capabilities;
        assert_eq!(
            handle_report_sandbox_configuration(&state, report(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }
    let mut stopped = state
        .store
        .get_message::<Sandbox>(SANDBOX)
        .await
        .unwrap()
        .unwrap();
    stopped.set_phase(SandboxPhase::Stopped.into());
    state.store.put_message(&stopped).await.unwrap();
    assert_no_loaded_observation(&state).await;
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    stopped.set_phase(SandboxPhase::Ready.into());
    state.store.put_message(&stopped).await.unwrap();

    // Users and another sandbox cannot assert supervisor evidence.
    let user_report = authed_request(report(accepted.clone()).into_inner());
    assert_eq!(
        handle_report_sandbox_configuration(&state, user_report)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        handle_report_sandbox_configuration(
            &state,
            with_sandbox(report(accepted.clone()), "other-sandbox")
        )
        .await
        .unwrap_err()
        .code(),
        tonic::Code::PermissionDenied
    );
    for mutation in 0..6 {
        let mut bad = accepted.clone();
        let evidence = bad.loaded_enforcement.as_mut().unwrap();
        match mutation {
            0 => evidence.sandbox_id = "other".into(),
            1 => evidence.instance_id = uuid::Uuid::new_v4().to_string(),
            2 => evidence.policy_version += 1,
            3 => evidence.policy_hash = "wrong".into(),
            4 => evidence.config_revision = evidence.config_revision.wrapping_add(1),
            _ => evidence.provider_env_revision = evidence.provider_env_revision.wrapping_add(1),
        }
        assert_eq!(
            handle_report_sandbox_configuration(&state, report(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Aborted
        );
    }
    let mut rejected = accepted.clone();
    rejected.state = ConfigurationAdmissionState::Rejected.into();
    rejected.loaded_enforcement = None;
    handle_report_sandbox_configuration(&state, report(rejected))
        .await
        .unwrap();
    assert_no_loaded_observation(&state).await;
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();
    policy_status(&state, current.version, PolicyStatus::Failed).await;
    assert_no_loaded_observation(&state).await;
    policy_status(&state, current.version, PolicyStatus::Loaded).await;
    // LOADED cannot resurrect failed evidence in either response field.
    assert_no_loaded_observation(&state).await;
    handle_report_sandbox_configuration(&state, report(accepted.clone()))
        .await
        .unwrap();

    // Runtime quarantine invalidates the producer's captured generation.
    engine.enter_fail_closed("fixture failed load").unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&guard, SANDBOX, &accepted)
            .await
            .is_err()
    );
    let failed_guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    assert!(
        engine
            .loaded_enforcement_evidence(&failed_guard, SANDBOX, &accepted)
            .await
            .is_err()
    );

    // A different current policy/configuration invalidates stored evidence even
    // before the supervisor reports its reload, and refuses the old receipt.
    let mut changed_policy = policy.clone();
    changed_policy.network_middlewares.clear();
    state
        .store
        .put_policy_revision(
            "receipt-policy-v2",
            SANDBOX,
            "default",
            2,
            &changed_policy.encode_to_vec(),
            &deterministic_policy_hash(&changed_policy),
        )
        .await
        .unwrap();
    assert_no_loaded_observation(&state).await;
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    let mut replacement = report(SandboxConfigurationAdmission {
        instance_id: uuid::Uuid::new_v4().to_string(),
        state: ConfigurationAdmissionState::Pending.into(),
        ..Default::default()
    });
    replacement.get_mut().expected_instance_id = instance.clone();
    handle_report_sandbox_configuration(&state, replacement)
        .await
        .unwrap();
    assert_no_loaded_observation(&state).await;
    assert_eq!(
        refresh_instance(&state, &instance)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        handle_report_sandbox_configuration(&state, report(accepted))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
}
