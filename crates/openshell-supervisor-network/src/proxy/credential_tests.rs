// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! External exchange admission through the trusted blocked-connect boundary.
use super::*;
use openshell_core::proposals::AgentProposals;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn resolve(pid: u32) -> ContractBinaryIdentity {
    static RESOLVER: std::sync::OnceLock<openshell_binary_identity::ProcfsIdentityResolver> =
        std::sync::OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            openshell_binary_identity::ProcfsIdentityResolver::for_process_tree(std::process::id())
        })
        .resolve(pid)
        .unwrap()
}

pub(super) async fn admit(
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

pub(crate) async fn admit_test_exchange_connection(
    engine: &OpaEngine,
    host: &str,
) -> crate::opa::ExchangeConnection {
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
        .exchange_connection
        .unwrap()
}

pub(crate) async fn handle_test_transparent_connection(
    stream: BoundaryDuplexStream,
    engine: Arc<OpaEngine>,
    tls: Option<Arc<ProxyTlsState>>,
    origin: SocketAddr,
    host: &str,
) -> Result<()> {
    let (admitted, decision) = admit(stream, &engine, host, Ok(resolve(std::process::id()))).await;
    assert_eq!(decision, TcpOpenDecision::RelayReady);
    let (stream, identity, addrs, mut transparent) = admitted.unwrap();
    // Substitute only the dial address after real blocked-connect admission.
    // TLS still verifies the admitted host; no upstream-proxy bypass is enabled.
    let (_, connector) = transparent
        .as_mut()
        .unwrap()
        .authorization
        .as_mut()
        .unwrap();
    *connector = destination::UpstreamConnector::new(host, 443, vec![origin]);
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
        Arc::new(None),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

pub(super) fn policy() -> openshell_core::proto::SandboxPolicy {
    openshell_policy::parse_sandbox_policy(
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
          - allow: { method: GET, path: /admitted }
"#,
    )
    .unwrap()
}

#[tokio::test]
async fn external_exchange_live_policy_selection_and_generation_binding() {
    let protected = policy();
    let engine = OpaEngine::from_proto(&protected).unwrap();
    let connection = admit_test_exchange_connection(&engine, "203.0.113.10").await;
    let guard = engine
        .generation_guard(engine.current_generation())
        .unwrap();
    let proof = connection.proof_for("203.0.113.10", 443, &guard).unwrap();
    assert!(!proof.policy_hash.is_empty());
    assert!(connection.proof_for("203.0.113.11", 443, &guard).is_err());
    assert!(connection.proof_for("203.0.113.10", 444, &guard).is_err());
    let unrelated = OpaEngine::from_proto(&protected).unwrap();
    assert!(
        connection
            .proof_for(
                "203.0.113.10",
                443,
                &unrelated
                    .generation_guard(unrelated.current_generation())
                    .unwrap()
            )
            .is_err()
    );

    let mut stock = protected.clone();
    stock.network_middlewares.clear();
    stock
        .network_policies
        .get_mut("provider")
        .unwrap()
        .binaries
        .push(openshell_core::proto::NetworkBinary {
            path: resolve(std::process::id())
                .executable
                .path
                .to_string_lossy()
                .into_owned(),
        });
    engine.reload_from_proto(&stock).unwrap();
    assert!(connection.proof_for("203.0.113.10", 443, &guard).is_err());
    let (stream, _peer) = tokio::io::duplex(4096);
    let (accepted, decision) = admit(
        Box::new(stream),
        &engine,
        "203.0.113.10",
        Ok(resolve(std::process::id())),
    )
    .await;
    assert_eq!(decision, TcpOpenDecision::RelayReady);
    assert!(
        accepted
            .unwrap()
            .3
            .unwrap()
            .authorization
            .unwrap()
            .0
            .endpoint
            .exchange_connection
            .is_none()
    );
    engine.reload_from_proto(&protected).unwrap();
    admit_test_exchange_connection(&engine, "203.0.113.10").await;
}

#[tokio::test]
async fn external_exchange_rejects_weak_conflicted_routes_and_unverified_source() {
    for variant in 0..7 {
        let mut policy = policy();
        let endpoint = &mut policy
            .network_policies
            .get_mut("provider")
            .unwrap()
            .endpoints[0];
        match variant {
            0 => endpoint.protocol = "tcp".into(),
            1 => endpoint.enforcement = openshell_core::proto::NetworkEnforcementMode::Audit as i32,
            2 => endpoint.rules.clear(),
            3 => endpoint.access = openshell_core::proto::NetworkAccessPreset::Full as i32,
            4 => {
                // A separately pinned L4 route must not escape the exchange guard.
                let mut weak = policy.network_policies["provider"].clone();
                weak.endpoints[0].protocol.clear();
                weak.endpoints[0].rules.clear();
                weak.binaries.push(openshell_core::proto::NetworkBinary {
                    path: "/other/process".into(),
                });
                policy.network_policies.insert("weak".into(), weak);
            }
            5 => {
                let mut duplicate = policy.network_middlewares["protected"].clone();
                duplicate.order = 1;
                policy
                    .network_middlewares
                    .insert("duplicate".into(), duplicate);
            }
            _ => {}
        }
        // Typed validation may reject malformed variants before admission.
        let Ok(engine) = OpaEngine::from_proto(&policy) else {
            continue;
        };
        let (stream, _peer) = tokio::io::duplex(4096);
        let identity = if variant == 6 {
            Err(ResolveError::Failed("unverified".into()))
        } else {
            Ok(resolve(std::process::id()))
        };
        let (accepted, decision) = admit(Box::new(stream), &engine, "203.0.113.10", identity).await;
        assert!(accepted.is_none(), "variant {variant}");
        assert!(
            matches!(decision, TcpOpenDecision::Denied(_)),
            "variant {variant}"
        );
    }
}

#[tokio::test]
async fn external_exchange_explicit_connect_legacy_and_host_identity_cannot_mint() {
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
            assert!(decision.endpoint.exchange_connection.is_none());
        } else {
            let decision = authorize_supplied_identity(
                &engine,
                &cache,
                EgressIntent::connect("203.0.113.10".into(), 443),
                &Ok(identity.clone()),
            );
            assert!(matches!(decision.action, NetworkAction::Deny { .. }));
            assert!(decision.endpoint.exchange_connection.is_none());
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
