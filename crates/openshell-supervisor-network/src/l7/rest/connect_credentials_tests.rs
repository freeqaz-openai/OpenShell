// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise trusted transparent admission and the actual common HTTP/TLS relay.
//! A local synthetic upstream proxy stands in for the provider; TEST-NET traffic
//! never leaves this process. Neither authority authentication nor TLS verification
//! is disabled. Linux is required for genuine backend identity resolution.

use super::*;
use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa};
use crate::upstream_proxy::{UpstreamProxyArgs, UpstreamProxyConfig};

const PROVIDER: &str = "203.0.113.10";

#[derive(Clone, Copy)]
enum Transport {
    Plaintext,
    PlaintextHttpsTarget,
    Tls,
    Downgrade,
    WrongCertificate,
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.expect("complete HTTP head"));
        assert!(head.len() < 8192);
    }
    head
}

async fn provider_http<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    response: &[u8],
) -> Vec<u8> {
    let mut received = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        assert!(received.len() < 8192);
        if received.ends_with(br#"{"model":"fixture-model"}"#)
            || received.starts_with(b"GET /protected-read HTTP/1.1\r\n")
                && received.ends_with(b"\r\n\r\n")
        {
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
            break;
        }
    }
    received
}

async fn workload_http<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    https_target: bool,
    no_material: bool,
) -> Vec<u8> {
    let body = br#"{"model":"fixture-model"}"#;
    // The explicit :443 defeats the plaintext branch's default-port mismatch:
    // this must reach the protected transport guard, not an authority mismatch.
    let target = if https_target {
        format!("https://{PROVIDER}:443/generate")
    } else {
        "/generate".into()
    };
    let request = if no_material {
        format!("GET {NO_MATERIAL_PATH} HTTP/1.1\r\nHost: {PROVIDER}:443\r\nCookie: forged\r\nProxy-Authorization: forged\r\nX-OpenShell-Credential: forged\r\nAuthorization: forged\r\n\r\n").into_bytes()
    } else {
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: {PROVIDER}:443\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        [request.as_bytes(), body].concat()
    };
    // A failed upstream handshake may close the workload side before its write.
    if stream.write_all(&request).await.is_err() {
        return Vec::new();
    }
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received).await;
    received
}

async fn transparent_exchange(
    fixture: &Fixture,
    transport: Transport,
    protected: bool,
    response: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut context = openshell_ocsf::ctx::ctx().clone();
    context.sandbox_id = SANDBOX.into();
    openshell_ocsf::ctx::set_ctx(context);
    assert_eq!(openshell_ocsf::ctx::ctx().sandbox_id, SANDBOX);

    let ca = SandboxCa::generate().unwrap();
    let mut workload_roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
        workload_roots.add(cert.unwrap()).unwrap();
    }
    let workload_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(workload_roots)
            .with_no_client_auth(),
    );
    let certificate_host = if matches!(transport, Transport::WrongCertificate) {
        "wrong-provider.test"
    } else {
        PROVIDER
    };
    let cert = rcgen::generate_simple_self_signed(vec![certificate_host.into()]).unwrap();
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
    let tls_state = Arc::new(ProxyTlsState::new(CertCache::new(ca), upstream_config));

    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_address = provider_listener.local_addr().unwrap();
    let provider = Box::pin(async {
        let (mut stream, _) = provider_listener.accept().await.unwrap();
        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
        let connect = read_head(&mut stream).await;
        assert!(connect.starts_with(format!("CONNECT {PROVIDER}:443 HTTP/1.1\r\n").as_bytes()));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        match transport {
            Transport::Plaintext | Transport::PlaintextHttpsTarget => {
                provider_http(stream, &response).await
            }
            Transport::Downgrade => {
                // Observe actual TLS bytes, then answer with plaintext. There is
                // no retry or plaintext fallback after the failed handshake.
                let mut hello = vec![0; 8192];
                let n = stream.read(&mut hello).await.unwrap();
                hello.truncate(n);
                assert_eq!(hello[0], 0x16);
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
                hello
            }
            Transport::Tls | Transport::WrongCertificate => {
                let handshake = tokio_rustls::TlsAcceptor::from(Arc::new(provider_config))
                    .accept(stream)
                    .await;
                if matches!(transport, Transport::WrongCertificate) {
                    assert!(handshake.is_err(), "hostname mismatch must reject TLS");
                    Vec::new()
                } else {
                    provider_http(handshake.expect("authenticated upstream TLS"), &response).await
                }
            }
        }
    });

    let mut policy = fixture.policy.clone();
    if !protected {
        policy.network_middlewares.clear();
    }
    let engine = Arc::new(crate::opa::OpaEngine::from_proto(&policy).unwrap());
    engine.set_middleware_runner_for_tests(fixture.runner.clone());
    let upstream_proxy = UpstreamProxyConfig::from_args(&UpstreamProxyArgs {
        https_proxy: Some(format!("http://{provider_address}")),
        proxy_connect_by_hostname: true,
        ..Default::default()
    })
    .unwrap();
    let (client, workload) = tokio::io::duplex(64 * 1024);
    let no_material = fixture.authority.behavior.no_material().is_some();
    let workload = Box::pin(async {
        if matches!(
            transport,
            Transport::Plaintext | Transport::PlaintextHttpsTarget
        ) {
            workload_http(
                workload,
                matches!(transport, Transport::PlaintextHttpsTarget),
                no_material,
            )
            .await
        } else {
            let stream = tokio_rustls::TlsConnector::from(workload_config)
                .connect(
                    rustls::pki_types::ServerName::try_from(PROVIDER).unwrap(),
                    workload,
                )
                .await
                .expect("workload TLS must complete independently of upstream TLS");
            workload_http(stream, false, no_material).await
        }
    });
    let adapter = Box::pin(
        crate::proxy::credential_tests::handle_test_transparent_connection(
            Box::new(client),
            engine,
            Some(tls_state),
            upstream_proxy,
            PROVIDER,
        ),
    );
    let (result, sent, safe) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(adapter, provider, workload)
    })
    .await
    .expect("CONNECT exchange must terminate");
    if matches!(
        transport,
        Transport::Downgrade | Transport::WrongCertificate
    ) {
        assert!(
            result.is_err(),
            "upstream TLS failure must close the adapter"
        );
    } else {
        result.unwrap();
    }
    (sent, safe)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_plaintext_protected_sends_zero_credentials_and_calls_no_authority() {
    for transport in [Transport::Plaintext, Transport::PlaintextHttpsTarget] {
        let fixture = Fixture::start_for_host(Behavior::Allow, 1024 * 1024, PROVIDER).await;
        let (sent, safe) = transparent_exchange(&fixture, transport, true, response(b"{}")).await;
        let observations = (
            fixture.authority.resolutions.load(Ordering::SeqCst),
            fixture.authority.authorizations.load(Ordering::SeqCst),
            fixture.authority.responses.load(Ordering::SeqCst),
            sent.windows(TOKEN.len())
                .filter(|w| *w == TOKEN.as_bytes())
                .count(),
            sent.len(),
        );
        assert_eq!(
            observations,
            (0, 0, 0, 0, 0),
            "independent authority and raw provider observations"
        );
        assert!(safe.starts_with(b"HTTP/1.1 403"));
        let response = std::str::from_utf8(&safe).unwrap();
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(body["error"], "middleware_failed");
        assert_eq!(
            body["detail"],
            "Request could not be processed by configured middleware"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_authenticated_upstream_tls_dispatches_once() {
    let fixture = Fixture::start_for_host(Behavior::Allow, 1024 * 1024, PROVIDER).await;
    let (sent, safe) = transparent_exchange(&fixture, Transport::Tls, true, response(b"{}")).await;
    assert!(
        String::from_utf8(sent)
            .unwrap()
            .contains(&format!("authorization: Bearer {TOKEN}\r\n"))
    );
    assert!(safe.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(safe.ends_with(b"{}"));
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.responses.load(Ordering::SeqCst), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_upstream_downgrade_or_wrong_certificate_never_resolves() {
    for transport in [Transport::Downgrade, Transport::WrongCertificate] {
        let fixture = Fixture::start_for_host(Behavior::Allow, 1024 * 1024, PROVIDER).await;
        let (sent, safe) = transparent_exchange(&fixture, transport, true, response(b"{}")).await;
        assert!(!sent.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
        assert!(safe.is_empty());
        assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 0);
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_plaintext_unprotected_preserves_ordinary_response_reason() {
    let fixture = Fixture::start_for_host(Behavior::Allow, 1024 * 1024, PROVIDER).await;
    let response =
        b"HTTP/1.1 200 Ordinary custom reason\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            .to_vec();
    let (sent, safe) =
        transparent_exchange(&fixture, Transport::Plaintext, false, response.clone()).await;
    assert!(sent.starts_with(b"POST /generate HTTP/1.1\r\n"));
    assert!(!sent.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    assert_eq!(safe, response);
    assert_eq!(fixture.authority.resolutions.load(Ordering::SeqCst), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_protected_response_never_releases_encoded_provider_reason() {
    use base64::Engine;
    let fixture = Fixture::start_for_host(Behavior::Allow, 1024 * 1024, PROVIDER).await;
    let encoded = base64::engine::general_purpose::STANDARD.encode(TOKEN);
    let response = format!("HTTP/1.1 200 {encoded}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").into_bytes();
    let (sent, safe) = transparent_exchange(&fixture, Transport::Tls, true, response).await;
    assert!(sent.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()));
    assert_eq!(fixture.authority.responses.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.authority.response_bodies.lock().unwrap(),
        vec![b"{}".to_vec()]
    );
    assert!(
        safe.ends_with(b"{}"),
        "approved innocuous body must be delivered"
    );
    assert!(
        !safe.windows(encoded.len()).any(|w| w == encoded.as_bytes()),
        "provider reason bypassed response policy"
    );
    assert!(safe.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn transparent_execution_authority_uses_verified_blocked_connect_without_executable_pin() {
    let fixture = Fixture::start_for_host(Behavior::ExecutionAllow, 1024 * 1024, PROVIDER).await;
    let (sent, safe) =
        transparent_exchange(&fixture, Transport::Tls, true, response(b"whole execution")).await;
    assert_eq!(
        sent.windows(TOKEN.len())
            .filter(|s| *s == TOKEN.as_bytes())
            .count(),
        1
    );
    assert!(safe.ends_with(b"whole execution"));
    assert_eq!(fixture.authority.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.responses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn transparent_protected_no_material_read_once_then_last_route_withdrawn() {
    let fixture = Fixture::start_for_host(
        Behavior::NoMaterial(NoMaterial::Allow),
        1024 * 1024,
        PROVIDER,
    )
    .await;
    let authority = &fixture.authority;
    let grants_and_response = || {
        (
            authority.access_grants.load(Ordering::SeqCst),
            authority.material_reads.load(Ordering::SeqCst),
            authority.send_grants.load(Ordering::SeqCst),
            authority.responses.load(Ordering::SeqCst),
        )
    };
    let (origin, received) = transparent_exchange(
        &fixture,
        Transport::Tls,
        true,
        response(b"protected read allowed"),
    )
    .await;
    // The complete origin observation: exactly one read, with neither ambient nor injected credentials.
    assert_eq!(
        origin,
        format!("GET {NO_MATERIAL_PATH} HTTP/1.1\r\nHost: {PROVIDER}:443\r\n\r\n").as_bytes()
    );
    assert!(received.ends_with(b"protected read allowed"));
    assert_eq!(grants_and_response(), (1, 0, 1, 1));

    authority.revoked.store(true, Ordering::SeqCst);
    let (origin, received) = transparent_exchange(
        &fixture,
        Transport::Tls,
        true,
        response(b"must never be read"),
    )
    .await;
    assert_eq!(origin, b"", "withdrawn route received no HTTP request");
    assert_eq!(received, REFUSED_RESPONSE);
    assert_eq!(
        authority.resolutions.load(Ordering::SeqCst),
        2,
        "next operation checked current authority"
    );
    assert_eq!(
        grants_and_response(),
        (1, 0, 1, 1),
        "withdrawal gave no new grants, reads or origin response"
    );
}
