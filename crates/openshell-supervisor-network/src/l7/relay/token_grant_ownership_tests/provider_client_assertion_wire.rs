// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTPS Gateway and OAuth broker with the real supervisor credential relay.
//! The workload and origin are the relay's existing duplex fixtures.

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Form, FromRequest, Request, State},
    http::{Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use openshell_core::{
    grpc_client::{GatewayEndpoint, fetch_provider_environment, fetch_settings_snapshot},
    oauth::DEFAULT_CLIENT_ASSERTION_TYPE,
    proto::{
        NetworkAccessPreset, NetworkBinary, NetworkEndpoint, ProviderCredentialTokenGrant,
        ProviderCredentialTokenGrantType, ProviderProfile, ProviderProfileCategory,
        ProviderProfileCredential,
    },
    provider_credentials::ProviderCredentialState,
    token_grant_failure::REQUEST_ID_HEADER,
};
use openshell_server::{
    TlsAcceptor,
    test_support::provider_grant::{PROVIDER_ID, ProviderGrantGateway, SANDBOX, SIBLING},
};
use serde::Deserialize;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

use super::{Capture, Connection, HOST, PORT, WAIT};
use crate::l7::L7EndpointConfig;
use crate::l7::relay::L7EvalContext;
use crate::l7::token_grant_injection::SpiffeTokenGrantResolver;
use crate::opa::{NetworkAction, NetworkInput, OpaEngine};
use crate::token_grant::SandboxInstanceTokenGrants;

const CHILD_CERT_DIR: &str = "OPENSHELL_PROVIDER_ASSERTION_WIRE_CERT_DIR";
const GATEWAY_ISSUER: &str = "openshell-gateway:wire-gateway";
const CREDENTIAL: &str = "access_token";
const ENV_KEY: &str = "WIRE_AUTHORIZATION";
const PLACEHOLDER_VALUE: &str = "fixture-placeholder-source";
const ACCESS_TOKEN: &str = "fixture-granted-access-token";
const RESOURCE_AUDIENCE: &str = "api://wire-origin";

#[derive(Clone, Copy)]
enum Placement {
    Bearer,
    GitBasic,
}

#[test]
fn provider_client_assertion_wire() {
    run_wire_test(
        concat!(module_path!(), "::provider_client_assertion_wire"),
        Placement::Bearer,
    );
}

#[test]
fn provider_client_assertion_git_basic_wire() {
    run_wire_test(
        concat!(module_path!(), "::provider_client_assertion_git_basic_wire"),
        Placement::GitBasic,
    );
}

fn run_wire_test(full_name: &str, placement: Placement) {
    if let Some(cert_dir) = std::env::var_os(CHILD_CERT_DIR) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(WAIT * 4, run(Path::new(&cert_dir), placement))
                    .await
                    .expect("bounded local wire test")
            });
        return;
    }

    // TLS trust is process configuration for both real clients. Give this case
    // an isolated process so other tests never observe its ephemeral CA.
    let cert_dir = tempfile::tempdir().unwrap();
    let pki = openshell_otel_test_support::TestPki::generate();
    for (name, pem) in [
        ("ca.pem", pki.ca_pem),
        ("server-cert.pem", pki.server.cert_pem),
        ("server-key.pem", pki.server.key_pem),
    ] {
        std::fs::write(cert_dir.path().join(name), pem).unwrap();
    }
    let ca = cert_dir.path().join("ca.pem");
    let (_, test_name) = full_name.split_once("::").expect("crate prefix");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_CERT_DIR, cert_dir.path())
        .env("SSL_CERT_FILE", &ca)
        .env_remove("SSL_CERT_DIR")
        .env(openshell_core::sandbox_env::TLS_CA, &ca)
        .env_remove(openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME)
        .output()
        .expect("run wire test with isolated certificate trust");
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
        "wire test subprocess failed\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

async fn run(cert_dir: &Path, placement: Placement) {
    openshell_crypto::tls::ensure_default_provider();
    let (auth_style, route, target, environment) = match placement {
        Placement::Bearer => (
            "bearer",
            "/wire",
            "/wire",
            &[(ENV_KEY, PLACEHOLDER_VALUE)][..],
        ),
        Placement::GitBasic => (
            "basic",
            "/team/repo.git/**",
            "/team/repo.git/info/refs?service=git-upload-pack",
            &[][..],
        ),
    };
    let tls = TlsAcceptor::from_files(
        &cert_dir.join("server-cert.pem"),
        &cert_dir.join("server-key.pem"),
        None,
        false,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("broker bind");
    let broker_url = format!(
        "https://localhost:{}/token",
        listener.local_addr().unwrap().port()
    );
    let binary = crate::test_support::executable_path("/usr/bin/curl");
    let gateway = ProviderGrantGateway::start(
        tls.clone(),
        profile(&broker_url, &binary, auth_style, route, environment),
        CREDENTIAL,
        &broker_url,
        environment,
    )
    .await;
    let broker = Broker::start(listener, tls.acceptor(), &broker_url, &gateway).await;

    let settings = fetch_settings_snapshot(&gateway.sandbox, SANDBOX)
        .await
        .expect("fetch gateway-composed policy over TLS");
    assert!(
        settings.configuration_admitted,
        "{}",
        settings.configuration_error
    );
    let policy = settings.policy.expect("gateway-composed provider policy");
    let engine = Arc::new(OpaEngine::from_proto(&policy).expect("provider policy compiles"));
    let delivery = fetch_provider_environment(&gateway.sandbox, SANDBOX)
        .await
        .expect("fetch real provider installation over TLS");
    assert!(
        delivery
            .dynamic_credentials
            .values()
            .any(
                |credential| credential.token_grant_provider_id == PROVIDER_ID
                    && credential.auth_style == auth_style
            ),
        "Gateway delivers the immutable provider identity and authored placement"
    );
    let state = ProviderCredentialState::from_bound_environment_with_stable_placeholders(
        delivery.provider_env_revision,
        delivery.environment,
        delivery.credential_expires_at_ms,
        delivery.dynamic_credentials,
        delivery.static_credential_bindings,
        delivery.non_secret_environment_keys,
        delivery.stable_placeholder_environment_keys,
    )
    .expect("provider installation accepted by supervisor");
    let child = state.snapshot();
    let basic = matches!(placement, Placement::GitBasic);
    let workload_header = if basic {
        assert!(!child.child_env.contains_key(ENV_KEY));
        "fixture-workload-auth"
    } else {
        let placeholder = &child.child_env[ENV_KEY];
        assert!(placeholder.starts_with("openshell:resolve:env:"));
        placeholder
    };
    assert!(
        child
            .child_env
            .values()
            .all(|value| { !value.contains(PLACEHOLDER_VALUE) && !value.contains(ACCESS_TOKEN) }),
        "workload environment excludes granted and stored credential values",
    );

    let relay = WireRelay::new(engine, state, &binary, workload_header, target);

    // The sibling has a valid session, but cannot mint for this sandbox.
    fetch_provider_environment(&gateway.sibling, SIBLING)
        .await
        .expect("sibling session authenticates for its own sandbox");
    relay.assert_refused(&gateway.sibling, 443).await;
    broker.assert_outcomes(&[]);

    let (response, capture) = relay.exchange(&gateway.sandbox, 443).await;
    assert!(
        response.starts_with("HTTP/1.1 204 "),
        "expected origin response"
    );
    let [origin] = capture.requests.as_slice() else {
        panic!("expected one request at the origin");
    };
    let values = origin
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .collect::<Vec<_>>();
    assert!(origin.starts_with(&format!("GET {target} HTTP/1.1\r\n")));
    let expected = if basic {
        let encoded = STANDARD.encode(format!("x-access-token:{ACCESS_TOKEN}"));
        assert!(!response.contains(&encoded));
        format!("Basic {encoded}")
    } else {
        format!("Bearer {ACCESS_TOKEN}")
    };
    assert!(
        values == [expected],
        "exactly one Authorization header carries the granted access token"
    );
    assert!(!origin.contains(workload_header));
    assert!(!origin.contains(PLACEHOLDER_VALUE));
    broker.assert_outcomes(&[Outcome::Issued]);

    *broker.state.audience.lock().unwrap() = format!("{broker_url}/other");
    relay.assert_refused(&gateway.sandbox, 443).await;
    broker.assert_outcomes(&[Outcome::Issued, Outcome::WrongAudience]);

    if basic {
        // A plaintext request to the very same endpoint cannot acquire a grant.
        relay.assert_refused(&gateway.sandbox, 80).await;
        broker.assert_outcomes(&[Outcome::Issued, Outcome::WrongAudience]);

        // Successful broker HTTP status cannot authorize encoding a malformed
        // access token. In particular, colon is valid in Basic's decoded
        // user:password form, but is forbidden in an OAuth token68 value.
        *broker.state.audience.lock().unwrap() = broker_url.clone();
        let malformed = "fixture-access:invalid";
        *broker.state.access_token.lock().unwrap() = malformed;
        let response = relay.assert_refused(&gateway.sandbox, 443).await;
        assert!(!response.contains(malformed));
        broker.assert_outcomes(&[Outcome::Issued, Outcome::WrongAudience, Outcome::Issued]);
    }
}

fn profile(
    broker_url: &str,
    binary: &Path,
    auth_style: &str,
    path: &str,
    environment: &[(&str, &str)],
) -> ProviderProfile {
    ProviderProfile {
        id: "wire-grant".into(),
        display_name: "Local wire grant".into(),
        category: ProviderProfileCategory::Other as i32,
        credentials: vec![ProviderProfileCredential {
            name: CREDENTIAL.into(),
            env_vars: environment.iter().map(|(key, _)| (*key).into()).collect(),
            auth_style: auth_style.into(),
            header_name: "Authorization".into(),
            token_grant: Some(ProviderCredentialTokenGrant {
                grant_type: ProviderCredentialTokenGrantType::OpenshellClientCredentials as i32,
                token_endpoint: broker_url.into(),
                audience: RESOURCE_AUDIENCE.into(),
                scopes: vec!["wire.read".into(), "wire.inspect".into()],
                ..Default::default()
            }),
            ..Default::default()
        }],
        endpoints: vec![NetworkEndpoint {
            host: HOST.into(),
            port: u32::from(PORT),
            path: path.into(),
            protocol: "rest".into(),
            access: NetworkAccessPreset::Full as i32,
            ..Default::default()
        }],
        binaries: vec![NetworkBinary {
            path: binary.to_str().unwrap().into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

struct WireRelay {
    engine: Arc<OpaEngine>,
    generation: u64,
    config: L7EndpointConfig,
    ctx: L7EvalContext,
    request: String,
}

impl WireRelay {
    fn new(
        engine: Arc<OpaEngine>,
        state: ProviderCredentialState,
        binary: &Path,
        workload_header: &str,
        target: &str,
    ) -> Self {
        let authorization = engine
            .authorize_egress(&NetworkInput {
                host: HOST.into(),
                port: PORT,
                binary_path: binary.into(),
                binary_sha256: "unused".into(),
                ancestors: vec![],
                cmdline_paths: vec![],
            })
            .expect("OPA resolves the provider route");
        let NetworkAction::Allow {
            matched_policy: Some(policy_name),
        } = authorization.action
        else {
            panic!("Gateway policy did not admit the fixture destination");
        };
        let [endpoint] = authorization.endpoint_configs.as_slice() else {
            panic!("expected one provider endpoint");
        };
        Self {
            engine,
            generation: authorization.generation,
            config: crate::l7::parse_l7_config(endpoint).unwrap(),
            ctx: L7EvalContext {
                host: HOST.into(),
                port: PORT,
                workspace: "default".into(),
                binary_path: binary.to_str().unwrap().into(),
                policy_name,
                provider_credentials: Some(state),
                ..Default::default()
            },
            request: format!(
                "GET {target} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\
                 Authorization: Bearer {workload_header}\r\n\
                 authorization: Bearer stale-value\r\nContent-Length: 0\r\n\r\n"
            ),
        }
    }

    async fn exchange(&self, caller: &GatewayEndpoint, default_port: u16) -> (String, Capture) {
        let ctx = L7EvalContext {
            request_default_port: Some(default_port),
            // Each case must reach the acquisition path instead of a cache hit.
            token_grant_resolver: Some(Arc::new(SpiffeTokenGrantResolver::new(
                SandboxInstanceTokenGrants::new(Some(caller.clone()), Some(SANDBOX.into()), None),
            ))),
            ..self.ctx.clone()
        };
        let mut connection = Connection::new(
            vec![self.config.clone()],
            self.engine.clone(),
            self.generation,
            ctx,
            None,
        );
        connection
            .app
            .write_all(self.request.as_bytes())
            .await
            .unwrap();
        let response = connection.response().await;
        assert!(
            response.contains("Content-Length: 0\r\n"),
            "empty workload response"
        );
        assert!(!response.contains(ACCESS_TOKEN));
        assert!(!response.contains(PLACEHOLDER_VALUE));
        (response, connection.finish().await)
    }

    async fn assert_refused(&self, caller: &GatewayEndpoint, default_port: u16) -> String {
        let (response, capture) = self.exchange(caller, default_port).await;
        assert!(
            response.starts_with("HTTP/1.1 502 "),
            "expected refused relay"
        );
        assert_eq!(
            capture.bytes_seen, 0,
            "refused request sent bytes to origin"
        );
        response
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Issued,
    WrongAudience,
    InvalidRequest,
    InvalidAssertion,
}

struct Broker {
    state: Arc<BrokerState>,
    accept_loop: JoinHandle<()>,
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

struct BrokerState {
    audience: Mutex<String>,
    access_token: Mutex<&'static str>,
    key_id: String,
    public_key: DecodingKey,
    outcomes: Mutex<Vec<Outcome>>,
}

impl Broker {
    async fn start(
        listener: TcpListener,
        tls: tokio_rustls::TlsAcceptor,
        audience: &str,
        gateway: &ProviderGrantGateway,
    ) -> Self {
        let jwks = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("broker discovery client")
            .get(format!("{}/.well-known/jwks.json", gateway.sandbox.url()))
            .send()
            .await
            .expect("fetch Gateway JWKS over TLS")
            .error_for_status()
            .expect("Gateway publishes verification key")
            .json::<JwkSet>()
            .await
            .expect("read Gateway JWKS");
        let [jwk] = jwks.keys.as_slice() else {
            panic!("expected one Gateway verification key");
        };
        let state = Arc::new(BrokerState {
            audience: Mutex::new(audience.into()),
            access_token: Mutex::new(ACCESS_TOKEN),
            key_id: jwk.common.key_id.clone().expect("Gateway key ID"),
            public_key: DecodingKey::from_jwk(jwk).expect("Gateway verification key"),
            outcomes: Mutex::default(),
        });
        let router = Router::new()
            .fallback(token_request)
            .with_state(state.clone());
        let accept_loop = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("broker accept");
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let tls = tls.clone();
                        let service = TowerToHyperService::new(router.clone());
                        connections.spawn(async move {
                            let stream = tls.accept(stream).await.expect("broker TLS");
                            Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(stream), service)
                                .await
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        let _ = completed.expect("broker connection").expect("broker task");
                    }
                }
            }
        });
        Self { state, accept_loop }
    }

    fn assert_outcomes(&self, expected: &[Outcome]) {
        assert_eq!(*self.state.outcomes.lock().unwrap(), expected);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthForm {
    grant_type: String,
    client_assertion_type: String,
    client_assertion: String,
    audience: String,
    scope: String,
}

#[derive(Deserialize)]
struct AssertionClaims {
    sub: String,
    sandbox_id: String,
    provider_id: String,
    credential_key: String,
    caller_kind: String,
}

async fn token_request(State(state): State<Arc<BrokerState>>, request: Request) -> Response {
    let outcome = state.verify(request).await;
    state.outcomes.lock().unwrap().push(outcome);
    if outcome == Outcome::Issued {
        Json(serde_json::json!({
            "access_token": *state.access_token.lock().unwrap(),
            "expires_in": 300,
            "token_type": "Bearer",
        }))
        .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response()
    }
}

impl BrokerState {
    async fn verify(&self, request: Request) -> Outcome {
        if request.method() != Method::POST
            || request.uri().path_and_query().map(|path| path.as_str()) != Some("/token")
            || request.headers().contains_key(header::AUTHORIZATION)
            || request
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| uuid::Uuid::parse_str(value).ok())
                .is_none()
        {
            return Outcome::InvalidRequest;
        }
        let Ok(Form(form)) = Form::<OAuthForm>::from_request(request, &()).await else {
            return Outcome::InvalidRequest;
        };
        if form.grant_type != "client_credentials"
            || form.client_assertion_type != DEFAULT_CLIENT_ASSERTION_TYPE
            || form.audience != RESOURCE_AUDIENCE
            || form.scope != "wire.read wire.inspect"
        {
            return Outcome::InvalidRequest;
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        validation.set_issuer(&[GATEWAY_ISSUER]);
        validation.set_audience(&[self.audience.lock().unwrap().as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
        let token = match openshell_crypto::jwt::decode::<AssertionClaims>(
            &form.client_assertion,
            &self.public_key,
            &validation,
        ) {
            Ok(token) => token,
            Err(error) if error.kind() == &jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                return Outcome::WrongAudience;
            }
            Err(_) => return Outcome::InvalidAssertion,
        };
        let claims = token.claims;
        if token.header.typ.as_deref() != Some("openshell-provider-assertion+jwt")
            || token.header.kid.as_deref() != Some(self.key_id.as_str())
            || claims.sub != format!("openshell-sandbox:{SANDBOX}")
            || claims.sandbox_id != SANDBOX
            || claims.provider_id != PROVIDER_ID
            || claims.credential_key != CREDENTIAL
            || claims.caller_kind != "supervisor"
        {
            return Outcome::InvalidAssertion;
        }

        Outcome::Issued
    }
}
