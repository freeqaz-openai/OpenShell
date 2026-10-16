// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload TLS through trusted transparent admission and the owning HTTP relay.
//! The finite authority/provider fixture is intentionally not an HTTP implementation.
#![cfg(target_os = "linux")]
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, external_http_exchange_capabilities,
};
use openshell_core::proto::middleware::v1::{
    http_installation_exchange_server::{HttpInstallationExchange, HttpInstallationExchangeServer},
    supervisor_middleware_server::{SupervisorMiddleware, SupervisorMiddlewareServer},
};
use openshell_core::proto::*;
use openshell_extension_core::{EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims};
use openshell_supervisor_middleware::{ChainRunner, MiddlewareRegistry};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_extension_core::{ExchangeKey, ExtensionCredentialStore};
use prost::Message;

const PROVIDER: &str = "203.0.113.10";
const QUERY: &str = "model=a%2Fb&n=1";

const AUDIENCE: &str = "urn:test:http-exchange";

const SANDBOX: &str = "immutable-sandbox-1";
const INSTANCE: &str = "11111111-1111-4111-8111-111111111111";
#[derive(Clone, Copy)]
enum Behavior {
    Allow,
    Refuse,
    Incomplete,
    FinalError,
    BadType,
    Oversize,
    LastTrailer,
    LostDownstream,
    Reload,
}
#[derive(Clone)]
struct Authority {
    key: DecodingKey,
    behavior: Behavior,
    payload_limit: u64,
    openings: Arc<AtomicUsize>,
    provider_completions: Arc<AtomicUsize>,
    before_reply: Arc<Notify>,
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
        let profile = external_http_exchange_capabilities();
        let mut metadata = extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            "test/authority",
            "1",
            profile.iter().copied().map(str::to_string),
        );
        metadata
            .required_capabilities
            .extend(profile.iter().copied().map(str::to_string));
        Ok(Response::new(MiddlewareManifest {
            name: "test/authority".into(),
            service_version: "1".into(),
            expected_audience: AUDIENCE.into(),
            extension: Some(metadata),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpExchange as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: self.payload_limit,
                request_timeout: None,
            }],
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
        let mut stream = request.into_inner();
        let authority = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            use installation_exchange_reply::Event as Reply;
            let mut challenge = [0; 32];
            aws_lc_rs::rand::fill(&mut challenge).unwrap();
            tx.send(Ok(InstallationExchangeReply {
                event: Some(Reply::Challenge(challenge.to_vec())),
            }))
            .await
            .unwrap();
            let installation_exchange_request::Event::Open(open) =
                stream.message().await.unwrap().unwrap().event.unwrap();
            let transcript = [
                b"openshell-http-exchange-v1\0".as_slice(),
                &challenge,
                &open.opening,
            ]
            .concat();
            aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, key)
                .verify(&transcript, &open.signature)
                .unwrap();
            let opening = HttpExchangeOpening::decode(open.opening.as_slice()).unwrap();
            assert_eq!(opening.audience, AUDIENCE);
            assert_eq!(opening.response_custody.len(), 32);
            assert_eq!(opening.verified_execution_policy_hash.len(), 64);
            let request = opening.request.unwrap();
            let context = request.context.unwrap();
            assert_eq!(context.sandbox_id, SANDBOX);
            let horizon = openshell_core::middleware::http_exchange_operation_horizon(
                &context.request_id,
                SystemTime::now(),
            )
            .unwrap();
            assert!(SystemTime::try_from(opening.deadline.unwrap()).unwrap() <= horizon);
            let target = request.target.unwrap();
            assert_eq!(
                (target.scheme.as_str(), target.host.as_str(), target.port),
                ("https", "203.0.113.10", 443)
            );
            assert_eq!(
                (target.method.as_str(), target.path.as_str()),
                ("POST", "/generate")
            );
            assert_eq!(target.query, QUERY);
            let mut headers: Vec<_> = request
                .headers
                .iter()
                .map(|h| (h.name.as_str(), h.value.as_str()))
                .collect();
            headers.sort_unstable();
            assert_eq!(
                headers,
                [("accept", "text/plain"), ("content-type", "text/plain")]
            );
            assert_eq!(request.body, b"payload");
            assert!(stream.message().await.unwrap().is_none());
            authority.openings.fetch_add(1, Ordering::SeqCst);
            authority.before_reply.notify_one();
            if matches!(
                authority.behavior,
                Behavior::LostDownstream | Behavior::Reload
            ) {
                // Hold the reply until the actual accepted stream/policy is revoked.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if matches!(authority.behavior, Behavior::Refuse) {
                let _ = tx
                    .send(Ok(InstallationExchangeReply {
                        event: Some(Reply::Refused(true)),
                    }))
                    .await;
                return;
            }
            // A finite provider on loopback. Only the authority connects/sends;
            // the relay's independent direct-origin stream must stay empty.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let last_trailer = matches!(authority.behavior, Behavior::LastTrailer);
            let cert = rcgen::generate_simple_self_signed(vec!["203.0.113.10".into()]).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.cert.der().clone()).unwrap();
            let client_tls = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let server_tls = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![cert.cert.der().clone()],
                        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())
                            .into(),
                    )
                    .unwrap(),
            );
            let provider = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                let mut stream = tokio_rustls::TlsAcceptor::from(server_tls)
                    .accept(stream)
                    .await
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"payload") {
                    bytes.push(stream.read_u8().await.unwrap());
                    assert!(bytes.len() <= 256);
                }
                assert_eq!(bytes, format!("POST /generate?{QUERY} HTTP/1.1\r\nHost: {PROVIDER}\r\nAuthorization: authority-only\r\naccept: text/plain\r\ncontent-type: text/plain\r\nContent-Length: 7\r\n\r\npayload").as_bytes());
                let trailer = if last_trailer { "deny" } else { "allow" };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n15\r\nPRIVATE_PROVIDER_BODY\r\n0\r\nDecision: {trailer}\r\n\r\n").as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            });
            let connection = TcpStream::connect(address).await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&connection);
            let mut connection =
                crate::l7::tls::tls_connect_upstream(connection, "203.0.113.10", &client_tls)
                    .await
                    .unwrap();
            let mut forwarded = format!(
                "{} {}?{} HTTP/1.1\r\nHost: {}\r\nAuthorization: authority-only\r\n",
                target.method, target.path, target.query, target.host
            );
            for (name, value) in headers {
                forwarded.push_str(&format!("{name}: {value}\r\n"));
            }
            forwarded.push_str(&format!("Content-Length: {}\r\n\r\n", request.body.len()));
            connection.write_all(forwarded.as_bytes()).await.unwrap();
            connection.write_all(&request.body).await.unwrap();
            let mut complete = Vec::new();
            connection.read_to_end(&mut complete).await.unwrap();
            provider.await.unwrap();
            assert!(
                complete.ends_with(b"Decision: deny\r\n\r\n")
                    || complete.ends_with(b"Decision: allow\r\n\r\n")
            );
            authority
                .provider_completions
                .fetch_add(1, Ordering::SeqCst);
            if complete.ends_with(b"Decision: deny\r\n\r\n") {
                let _ = tx
                    .send(Ok(InstallationExchangeReply {
                        event: Some(Reply::Refused(true)),
                    }))
                    .await;
                return;
            }
            assert!(complete.ends_with(b"Decision: allow\r\n\r\n"));
            let response = InstallationExchangeResponse {
                status: 200,
                content_type: if matches!(authority.behavior, Behavior::BadType) {
                    "text/plain\r\nInjected: yes"
                } else {
                    "text/plain"
                }
                .into(),
                body: if matches!(authority.behavior, Behavior::Oversize) {
                    vec![0; 2048]
                } else {
                    b"approved".to_vec()
                },
                response_complete: !matches!(authority.behavior, Behavior::Incomplete),
            };
            let _ = tx
                .send(Ok(InstallationExchangeReply {
                    event: Some(Reply::Response(response)),
                }))
                .await;
            if matches!(authority.behavior, Behavior::FinalError) {
                let _ = tx.send(Err(Status::internal("PRIVATE_DIAGNOSTIC"))).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
struct Fixture {
    policy: SandboxPolicy,
    authority: Authority,
    runner: ChainRunner,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn start(behavior: Behavior) -> Self {
        let payload_limit = 1024;
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
        let claims = ExtensionJwtClaims {
            exchange_key: Some(ExchangeKey {
                profile: "openshell-http-exchange-v1".into(),
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(key),
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
            key: DecodingKey::from_ed_pem(signing.public_key_pem().as_bytes()).unwrap(),
            behavior,
            payload_limit,
            openings: Arc::new(AtomicUsize::new(0)),
            provider_completions: Arc::new(AtomicUsize::new(0)),
            before_reply: Arc::new(Notify::new()),
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
                    seconds: 2,
                    nanos: 0,
                }),
                allow_insecure_transport: false,
            }],
            &HashMap::from([("test/authority".into(), token_slot.clone())]),
        )
        .await
        .unwrap();
        let runner = ChainRunner::from_registry(registry);

        let policy = openshell_policy::parse_sandbox_policy(
            r#"
version: 1
network_middlewares:
  protected:
    middleware: test/authority
    external_http_exchange: true
    endpoints: { include: ["203.0.113.10"] }
network_policies:
  provider:
    endpoints:
      - host: "203.0.113.10"
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: POST, path: /generate }
"#,
        )
        .unwrap();
        Self {
            policy,
            authority,
            runner,
            server,
        }
    }
    async fn relay(&self, path: &str, missing_authority: bool) -> Vec<u8> {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa};

        let mut context = openshell_ocsf::ctx::ctx().clone();
        context.sandbox_id = SANDBOX.into();
        openshell_ocsf::ctx::set_ctx(context);
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let workload_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let cert = rcgen::generate_simple_self_signed(vec![PROVIDER.into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let upstream_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let origin_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())
                        .into(),
                )
                .unwrap(),
        );
        let tls = Arc::new(ProxyTlsState::new(CertCache::new(ca), upstream_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = async {
            let (socket, _) = listener.accept().await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&socket);
            // The existing verified handshake is permitted. Only decrypted HTTP
            // bytes are forbidden on this separately observed original stream.
            let mut socket = tokio_rustls::TlsAcceptor::from(origin_config)
                .accept(socket)
                .await
                .unwrap();
            let mut byte = [0];
            match socket.read(&mut byte).await {
                Ok(0) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) => {}
                other => panic!("original TLS stream received HTTP bytes: {other:?}"),
            }
        };
        let engine = Arc::new(crate::opa::OpaEngine::from_proto(&self.policy).unwrap());
        if !missing_authority {
            engine.set_middleware_runner_for_tests(self.runner.clone());
        }
        let (client, workload) = tokio::io::duplex(8192);
        let adapter = Box::pin(
            crate::proxy::credential_tests::handle_test_transparent_connection(
                Box::new(client),
                engine.clone(),
                Some(tls),
                address,
                PROVIDER,
            ),
        );
        let workload = async {
            let mut stream = tokio_rustls::TlsConnector::from(workload_config)
                .connect(
                    rustls::pki_types::ServerName::try_from(PROVIDER).unwrap(),
                    workload,
                )
                .await
                .unwrap();
            stream.write_all(format!("POST {path}?{QUERY} HTTP/1.1\r\nHost: {PROVIDER}:443\r\nAuthorization: forged\r\nCookie: forged\r\nX-Control: forged\r\nAccept: text/plain\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\npayload").as_bytes()).await.unwrap();
            if matches!(
                self.authority.behavior,
                Behavior::LostDownstream | Behavior::Reload
            ) {
                self.authority.before_reply.notified().await;
                if matches!(self.authority.behavior, Behavior::Reload) {
                    engine.reload_from_proto(&SandboxPolicy::default()).unwrap();
                } else {
                    stream.shutdown().await.unwrap();
                }
            }
            let mut received = Vec::new();
            if let Err(e) = stream.read_to_end(&mut received).await {
                assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            received
        };
        let (result, (), received) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(adapter, origin, workload)
        })
        .await
        .expect("transparent exchange must terminate");
        result.unwrap();
        for private in [
            b"PRIVATE_DIAGNOSTIC".as_slice(),
            b"PRIVATE_PROVIDER_BODY",
            b"authority-only",
            b"Decision:",
        ] {
            assert!(!received.windows(private.len()).any(|w| w == private));
        }
        received
    }
}

#[tokio::test]
async fn external_exchange_transparent_tls_success() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let returned = fixture.relay("/generate", false).await;
    assert_eq!(returned, b"HTTP/1.1 200 Response\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\napproved");
    assert_eq!(fixture.authority.openings.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .authority
            .provider_completions
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn external_exchange_transparent_tls_refusal_never_falls_back() {
    for behavior in [
        Behavior::Refuse,
        Behavior::Incomplete,
        Behavior::FinalError,
        Behavior::LastTrailer,
        Behavior::BadType,
        Behavior::Oversize,
    ] {
        let fixture = Fixture::start(behavior).await;
        let returned = fixture.relay("/generate", false).await;
        assert!(returned.starts_with(b"HTTP/1.1 502"));
        assert!(!returned.windows(8).any(|w| w == b"approved"));
        assert_eq!(fixture.authority.openings.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .authority
                .provider_completions
                .load(Ordering::SeqCst),
            usize::from(!matches!(behavior, Behavior::Refuse))
        );
    }
}

#[tokio::test]
async fn external_exchange_transparent_tls_denied_route_never_opens() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let returned = fixture.relay("/denied", false).await;
    assert!(returned.starts_with(b"HTTP/1.1 403"));
    assert_eq!(fixture.authority.openings.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn external_exchange_transparent_tls_missing_authority_never_falls_back() {
    let fixture = Fixture::start(Behavior::Allow).await;
    let returned = fixture.relay("/generate", true).await;
    assert!(returned.starts_with(b"HTTP/1.1 403"));
    assert_eq!(fixture.authority.openings.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn external_exchange_transparent_tls_revocation_never_releases() {
    for behavior in [Behavior::LostDownstream, Behavior::Reload] {
        let fixture = Fixture::start(behavior).await;
        let returned = fixture.relay("/generate", false).await;
        assert!(!returned.windows(8).any(|w| w == b"approved"));
        assert_eq!(fixture.authority.openings.load(Ordering::SeqCst), 1);
    }
}
