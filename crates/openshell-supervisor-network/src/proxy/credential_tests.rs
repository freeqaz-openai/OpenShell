// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Synthetic trusted backend inputs, using the real procfs executable resolver.
//! No post-connect socket-owner lookup is accepted as credential provenance.
use super::*;
use openshell_core::proposals::AgentProposals;
use std::net::{Ipv4Addr, Ipv6Addr};

fn resolve(pid: u32) -> ContractBinaryIdentity {
    static RESOLVER: std::sync::OnceLock<openshell_binary_identity::ProcfsIdentityResolver> =
        std::sync::OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            openshell_binary_identity::ProcfsIdentityResolver::for_process_tree(std::process::id())
        })
        .resolve(pid)
        .unwrap()
}

async fn admit(
    stream: BoundaryDuplexStream,
    engine: &OpaEngine,
    host: &str,
    identity: Result<ContractBinaryIdentity, ResolveError>,
) -> (Option<AcceptedProxyConnection>, TcpOpenDecision) {
    let store = Arc::new(ResolvedEndpointStore::new(
        crate::policy_dns::StoreConfig::new(
            crate::policy_dns::SyntheticPools::new(
                Ipv4Addr::new(198, 18, 0, 2)..=Ipv4Addr::new(198, 18, 0, 9),
                "fd00:1::1".parse::<Ipv6Addr>().unwrap()..="fd00:1::8".parse::<Ipv6Addr>().unwrap(),
            )
            .unwrap(),
            16,
        )
        .unwrap(),
    ));
    let destination = if let Ok(ip) = host.parse::<IpAddr>() {
        SocketAddr::new(ip, 443)
    } else {
        let record = store
            .publish(
                crate::policy_dns::PublishRequest {
                    normalized_name: crate::policy_dns::NormalizedName::parse(host).unwrap(),
                    family: crate::policy_dns::AddressFamily::Ipv4,
                    allocation_identity: [1; 32],
                    policy_generation: engine.current_generation(),
                    ttl: std::time::Duration::from_secs(30),
                    contracts: vec![crate::policy_dns::ResolvedPortContract {
                        endpoint_id: PolicyEndpointId {
                            policy_name: "provider".into(),
                            endpoint_index: 0,
                        },
                        port: 443,
                        destination_plan: DestinationValidationPlan {
                            address_authorization:
                                destination::AddressAuthorization::ExactDeclaredHost,
                        },
                        pinned_addresses: vec!["203.0.113.8".parse().unwrap()],
                    }],
                },
                engine.current_generation(),
                std::time::Instant::now(),
            )
            .unwrap();
        SocketAddr::new(record.synthetic_address, 443)
    };
    let (decision, completion) = tokio::sync::oneshot::channel();
    let pending = PendingTcpOpen {
        stream,
        binary_identity: identity,
        destination,
        // Metadata is synthetic; the test exercises the trusted backend boundary,
        // not seccomp installation or the broker's socket registry itself.
        socket: openshell_isolation_interface::contract::NetworkSocketMetadata {
            socket_cookie: 7,
            nonblocking: false,
            process_generation: 1,
        },
        policy_generation: engine.current_generation(),
        timing: MediationTiming::default(),
        decision,
    };
    let admitted = preauthorize_transparent_open(
        pending,
        Some(&store),
        engine,
        &BinaryIdentityCache::new(),
        None,
        None,
        false,
        None,
    )
    .await;
    (admitted, completion.await.unwrap())
}

pub(crate) async fn admit_test_credential_connection(
    engine: &OpaEngine,
    host: &str,
) -> crate::opa::CredentialConnection {
    let (stream, _peer) = tokio::io::duplex(4096);
    let (admitted, decision) = admit(
        Box::new(stream),
        engine,
        host,
        Ok(resolve(std::process::id())),
    )
    .await;
    assert_eq!(decision, TcpOpenDecision::RelayReady);
    admitted
        .unwrap()
        .3
        .unwrap()
        .authorization
        .unwrap()
        .0
        .endpoint
        .credential_connection
        .unwrap()
}

pub(crate) async fn handle_test_transparent_connection(
    stream: BoundaryDuplexStream,
    engine: Arc<OpaEngine>,
    tls: Option<Arc<ProxyTlsState>>,
    upstream: Option<UpstreamProxyConfig>,
    host: &str,
) -> Result<()> {
    let (admitted, decision) = admit(stream, &engine, host, Ok(resolve(std::process::id()))).await;
    assert_eq!(decision, TcpOpenDecision::RelayReady);
    let (stream, identity, addrs, transparent) = admitted.unwrap();
    handle_mediated_connection(
        tokio::io::BufReader::new(stream),
        identity,
        addrs,
        transparent,
        None,
        engine,
        Arc::new(BinaryIdentityCache::new()),
        Arc::new(AtomicU32::new(std::process::id())),
        tls,
        None,
        AgentProposals::default(),
        Arc::new(None),
        Arc::new(None),
        Arc::new(upstream),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

fn policy() -> openshell_core::proto::SandboxPolicy {
    use sha2::{Digest, Sha256};
    let path = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let digest = hex::encode(Sha256::digest(std::fs::read(&path).unwrap()));
    let path = serde_json::to_string(&path).unwrap();
    openshell_policy::parse_sandbox_policy(&format!(
        r#"
version: 1
network_middlewares:
  protected:
    middleware: test/authority
    credential_authority: true
    credential_connectors: [{{ path: {path}, sha256: "{digest}" }}]
    endpoints: {{ include: ["203.0.113.10"] }}
network_policies:
  provider:
    endpoints: [{{ host: "203.0.113.10", port: 443 }}]
    binaries: [{{ path: {path} }}]
"#
    ))
    .unwrap()
}

#[tokio::test]
async fn transparent_credential_parent_admitted_child_denied_despite_ancestor_and_weaker_route() {
    let parent = resolve(std::process::id());
    let mut child = tokio::process::Command::new("/usr/bin/sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let child_identity = resolve(child.id().unwrap());
    assert_eq!(
        child_identity.executable.path,
        std::fs::canonicalize("/usr/bin/sleep").unwrap()
    );
    assert!(
        child_identity
            .ancestors
            .iter()
            .any(|a| a.path == parent.executable.path)
    );
    let mut protected = policy();
    // Show that the actual ancestor rule admits the child without credentials.
    let mut ordinary = protected.clone();
    ordinary.network_middlewares.clear();
    let cache = BinaryIdentityCache::new();
    let intent = || EgressIntent::connect("203.0.113.10".into(), 443);
    assert!(matches!(
        authorize_supplied_identity(
            &OpaEngine::from_proto(&ordinary).unwrap(),
            &cache,
            intent(),
            &Ok(child_identity.clone())
        )
        .action,
        NetworkAction::Allow { .. }
    ));
    // An additional route directly admits the child too; protected selection
    // must remain independent of which ordinary policy wins.
    let mut weak = protected.network_policies["provider"].clone();
    weak.name = "weak".into();
    weak.binaries[0].path = child_identity
        .executable
        .path
        .to_string_lossy()
        .into_owned();
    protected.network_policies.insert("weak".into(), weak);
    {
        let engine = OpaEngine::from_proto(&protected).unwrap();
        let (stream, mut peer) = tokio::io::duplex(4096);
        let (tuple, completion) = admit(
            Box::new(stream),
            &engine,
            "203.0.113.10",
            Ok(child_identity.clone()),
        )
        .await;
        assert_eq!(
            completion,
            TcpOpenDecision::Denied(TcpOpenDenial::PolicyDenied)
        );
        assert!(
            tuple.is_none(),
            "denied child cannot be dispatched or access credentials"
        );
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let connection = admit_test_credential_connection(&engine, "203.0.113.10").await;
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let proof = connection.proof_for("203.0.113.10", 443, &guard).unwrap();
        let openshell_core::middleware::VerifiedCredentialOrigin::Connector(proof) = proof else {
            panic!("old grant broadened");
        };
        assert_eq!(proof.path, parent.executable.path.to_string_lossy());
        assert_eq!(proof.sha256, parent.executable.digest.unwrap().to_string());
        assert!(connection.proof_for("203.0.113.11", 443, &guard).is_err());
        assert!(connection.proof_for("203.0.113.10", 444, &guard).is_err());
    }
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn transparent_credential_substituted_missing_and_ambiguous_pins_deny_before_dispatch() {
    let identity = resolve(std::process::id());
    for variant in 0..4 {
        let mut policy = policy();
        match variant {
            0 => {
                policy
                    .network_middlewares
                    .get_mut("protected")
                    .unwrap()
                    .credential_connectors[0]
                    .path = "/different/client".into()
            }
            1 => {
                policy
                    .network_middlewares
                    .get_mut("protected")
                    .unwrap()
                    .credential_connectors[0]
                    .sha256 = "b".repeat(64)
            }
            2 => {
                let mut second = policy.network_middlewares["protected"].clone();
                second.order = 1;
                policy
                    .network_middlewares
                    .insert("ambiguous".into(), second);
            }
            _ => {}
        }
        let engine = OpaEngine::from_proto(&policy).unwrap();
        let (stream, _peer) = tokio::io::duplex(4096);
        let supplied = if variant == 3 {
            Err(ResolveError::Failed("unverified".into()))
        } else {
            Ok(identity.clone())
        };
        let (tuple, completion) = admit(Box::new(stream), &engine, "203.0.113.10", supplied).await;
        assert!(tuple.is_none());
        assert_eq!(
            completion,
            TcpOpenDecision::Denied(if variant == 3 {
                TcpOpenDenial::IdentityUnavailable
            } else {
                TcpOpenDenial::PolicyDenied
            })
        );
    }
    for malformed in [false, true] {
        let mut policy = policy();
        let pins = &mut policy
            .network_middlewares
            .get_mut("protected")
            .unwrap()
            .credential_connectors;
        if malformed {
            pins[0].sha256 = "NOT_A_DIGEST".into();
        } else {
            pins.clear();
        }
        assert!(OpaEngine::from_proto(&policy).is_err());
    }
}

#[tokio::test]
async fn explicit_connect_legacy_and_host_exact_pinned_identity_cannot_mint() {
    let engine = Arc::new(OpaEngine::from_proto(&policy()).unwrap());
    let identity = resolve(std::process::id());
    for mode in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut workload = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = listener.accept().await.unwrap();
        let addrs = Some((client.peer_addr().unwrap(), client.local_addr().unwrap()));
        let cache = Arc::new(BinaryIdentityCache::new());
        if mode == 0 {
            let decision = authorize_egress_intent(
                crate::procfs::WorkloadProxyTcpConnection::new(addrs.unwrap().0, addrs.unwrap().1),
                &engine,
                &cache,
                &AtomicU32::new(std::process::id()),
                EgressIntent::connect("203.0.113.10".into(), 443),
            );
            assert_eq!(decision.binary.as_ref(), Some(&identity.executable.path));
            assert!(matches!(decision.action, NetworkAction::Deny { .. }));
            assert!(decision.endpoint.credential_connection.is_none());
        } else {
            let decision = authorize_supplied_identity(
                &engine,
                &cache,
                EgressIntent::connect("203.0.113.10".into(), 443),
                &Ok(identity.clone()),
            );
            assert!(matches!(decision.action, NetworkAction::Deny { .. }));
            assert!(decision.endpoint.credential_connection.is_none());
        }
        workload
            .write_all(b"CONNECT 203.0.113.10:443 HTTP/1.1\r\nHost: 203.0.113.10:443\r\n\r\n")
            .await
            .unwrap();
        let adapter = handle_mediated_connection(
            tokio::io::BufReader::new(Box::new(client)),
            (mode != 0).then(|| Ok(identity.clone())),
            if mode == 2 { None } else { addrs },
            None,
            None,
            engine.clone(),
            cache,
            Arc::new(AtomicU32::new(std::process::id())),
            None,
            None,
            AgentProposals::default(),
            Arc::new(None),
            Arc::new(None),
            Arc::new(None),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let mut response = Vec::new();
        let (result, _) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(adapter, workload.read_to_end(&mut response))
        })
        .await
        .unwrap();
        result.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
    }
}
