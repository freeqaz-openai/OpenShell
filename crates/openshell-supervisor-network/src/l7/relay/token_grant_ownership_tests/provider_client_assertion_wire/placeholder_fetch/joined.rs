// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Two local fixtures compose the supervisor's normal inspected relay with
//! an independent grant authority. Only the TLS origin socket is mapped to
//! loopback. Git, policy, middleware and assertion still use their real wire
//! contracts. The authority observes issuance and origin requests separately.

use super::*;

use std::collections::HashMap;
use std::net::IpAddr;

use openshell_core::proto::{
    MiddlewareEndpointSelector, NetworkMiddlewareConfig, SupervisorMiddlewareService,
};
use openshell_server::test_support::provider_grant::{
    ProviderGrantIdentity, middleware_credential,
};
use openshell_supervisor_middleware::{MAX_MIDDLEWARE_PAYLOAD_BYTES, MiddlewareRegistry};
use tokio::io::{AsyncBufReadExt, BufReader};

const CONFIG: &str = "OPENSHELL_PLACEHOLDER_WIRE_JOIN";
const GITHUB: &str = "github.com";
const GIT_KEY: &str = "GITHUB_TOKEN";

#[derive(Deserialize)]
struct Join {
    token_endpoint: String,
    token_ca: PathBuf,
    issuer: String,
    key_id: String,
    signing_key: PathBuf,
    public_key: PathBuf,
    sandbox_id: String,
    provider_id: String,
    credential_key: String,
    audience: String,
    workspace: String,
    middleware_name: String,
    middleware_endpoint: String,
    middleware_bearer: String,
    origin_host: IpAddr,
    origin_port: u16,
    origin_ca: PathBuf,
    origin_server_name: String,
    git_url: String,
    git_environment: HashMap<String, String>,
    git_client_prelude: String,
    node_binary: PathBuf,
    expected_oid: String,
    first_fetch_receipt: PathBuf,
    withdrawal_ready: PathBuf,
    withdrawn_fetch_receipt: PathBuf,
}

#[derive(Deserialize)]
struct Withdrawal {
    withdrawn_oid: String,
}

#[test]
#[ignore = "requires the local OCE grant and Git origin fixture"]
fn provider_client_assertion_occ_git_wire() {
    let path = std::env::var_os(CONFIG).expect("local grant fixture config");
    let config: Join = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let token_ca = config.token_ca.clone();
    with_tls_fixture(
        concat!(module_path!(), "::provider_client_assertion_occ_git_wire"),
        Some(&token_ca),
        |cert_dir| run_bounded(exercise_join(cert_dir, config), WAIT * 5),
    );
}

async fn exercise_join(cert_dir: &Path, join: Join) {
    openshell_crypto::tls::ensure_default_provider();
    // Middleware reads the supervisor identity from its bound instance context.
    // This fixture uses an isolated current-thread runtime.
    let mut context = (*openshell_ocsf::ctx::ctx()).clone();
    context.sandbox_id.clone_from(&join.sandbox_id);
    context.sandbox_name.clone_from(&join.sandbox_id);
    openshell_ocsf::ctx::bind_thread_ctx(Some(Arc::new(context)));
    assert!(join.origin_host.is_loopback());
    for endpoint in [&join.token_endpoint, &join.middleware_endpoint] {
        let endpoint = reqwest::Url::parse(endpoint).unwrap();
        assert_eq!(endpoint.scheme(), "https");
        assert_eq!(endpoint.host_str(), Some("localhost"));
        assert!(endpoint.port().is_some());
    }
    let path = join.git_url.strip_prefix("https://github.com/").unwrap();
    let route = format!("/{path}/**");
    let binary = Path::new("/usr/bin/git");
    let mut profile = profile(&join.token_endpoint, binary, "placeholder", &route, &[]);
    profile.endpoints[0].host = GITHUB.into();
    profile.endpoints[0].port = 443;
    profile.credentials[0].name.clone_from(&join.credential_key);
    profile.credentials[0].env_vars = vec![GIT_KEY.into()];
    let grant = profile.credentials[0].token_grant.as_mut().unwrap();
    grant.audience.clone_from(&join.audience);
    grant.scopes.clear();
    grant.cache_ttl = Some(prost_types::Duration::default());

    let gateway = ProviderGrantGateway::start_with_identity(
        gateway_tls(cert_dir),
        profile,
        &join.credential_key,
        &join.token_endpoint,
        &[],
        ProviderGrantIdentity {
            sandbox_id: &join.sandbox_id,
            provider_id: &join.provider_id,
            gateway_name: &join.issuer,
            key_id: &join.key_id,
            signing_pem: &std::fs::read(&join.signing_key).unwrap(),
            public_pem: &std::fs::read(&join.public_key).unwrap(),
        },
    )
    .await;
    let mut policy = gateway_policy(&gateway.sandbox, &join.sandbox_id).await;
    policy.network_middlewares.insert(
        "approve".into(),
        NetworkMiddlewareConfig {
            name: "approve".into(),
            middleware: join.middleware_name.clone(),
            config: Some(prost_types::Struct {
                fields: [(
                    "binding_id".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(join.audience.clone())),
                    },
                )]
                .into(),
            }),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec![GITHUB.into()],
                exclude: vec![],
            }),
            ..Default::default()
        },
    );
    let engine = Arc::new(OpaEngine::from_proto(&policy).unwrap());
    let registry = MiddlewareRegistry::connect_services_authenticated(
        vec![],
        vec![SupervisorMiddlewareService {
            name: join.middleware_name.clone(),
            grpc_endpoint: join.middleware_endpoint.clone(),
            tls_ca_cert_pem: std::fs::read(&join.token_ca).unwrap(),
            audience: "repository-set".into(),
            max_payload_bytes: MAX_MIDDLEWARE_PAYLOAD_BYTES as u64,
            request_timeout: Some(prost_types::Duration {
                seconds: 5,
                nanos: 0,
            }),
            ..Default::default()
        }],
        &middleware_credential(join.middleware_name.clone(), &join.middleware_bearer),
    )
    .await
    .expect("authenticate to the real grant admission middleware");
    engine.replace_middleware_registry(registry).unwrap();

    let delivery = fetch_provider_environment(&gateway.sandbox, &join.sandbox_id)
        .await
        .unwrap();
    assert!(
        delivery.environment.is_empty(),
        "credential issuance is cold"
    );
    let state = provider_state(delivery);
    let handle = state.snapshot().child_env[GIT_KEY].clone();
    let authorization = engine
        .authorize_egress(&NetworkInput {
            host: GITHUB.into(),
            port: 443,
            binary_path: binary.into(),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        })
        .unwrap();
    let NetworkAction::Allow {
        matched_policy: Some(policy_name),
    } = authorization.action
    else {
        panic!("joint Git origin must pass the provider's L4 policy");
    };
    let configs: Vec<_> = authorization
        .endpoint_configs
        .iter()
        .filter_map(crate::l7::parse_l7_config)
        .collect();
    assert_eq!(configs.len(), 1);
    let context = L7EvalContext {
        host: GITHUB.into(),
        port: 443,
        request_default_port: Some(443),
        binary_path: binary.to_str().unwrap().into(),
        workspace: join.workspace.clone(),
        policy_name,
        provider_credentials: Some(state),
        token_grant_resolver: Some(Arc::new(SpiffeTokenGrantResolver::new(
            SandboxInstanceTokenGrants::new(
                Some(gateway.sandbox.clone()),
                Some(join.sandbox_id.clone()),
                None,
            ),
        ))),
        ..Default::default()
    };

    let ca = SandboxCa::generate().unwrap();
    let ca_path = cert_dir.join("proxy-ca.pem");
    std::fs::write(&ca_path, ca.cert_pem()).unwrap();
    let tls = Arc::new(ProxyTlsState::new(
        CertCache::new(ca),
        build_upstream_client_config(&std::fs::read_to_string(&join.origin_ca).unwrap()).unwrap(),
    ));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let origin = (join.origin_host, join.origin_port);
    let origin_server_name = join.origin_server_name.clone();
    let proxy = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = tls.clone();
            let engine = engine.clone();
            let configs = configs.clone();
            let context = context.clone();
            let origin_server_name = origin_server_name.clone();
            let generation = authorization.generation;
            tokio::spawn(async move {
                let mut client = BufReader::new(socket);
                let mut line = String::new();
                client.read_line(&mut line).await.unwrap();
                assert_eq!(line, "CONNECT github.com:443 HTTP/1.1\r\n");
                loop {
                    line.clear();
                    assert_ne!(client.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                let mut client = crate::l7::tls::tls_terminate_client(client, &tls, GITHUB)
                    .await
                    .unwrap();
                let upstream = openshell_core::net::connect_tcp_nodelay_best_effort(origin)
                    .await
                    .unwrap();
                let mut upstream = crate::l7::tls::tls_connect_upstream(
                    upstream,
                    &origin_server_name,
                    tls.upstream_config(),
                )
                .await
                .unwrap();
                let evaluator = engine.clone_engine_for_tunnel(generation).unwrap();
                crate::proxy::relay_inspected_http_stream_for_test(
                    &mut client,
                    &mut upstream,
                    configs,
                    evaluator,
                    &engine,
                    &context,
                )
                .await
                .unwrap();
            });
        }
    });

    fetch_fresh(
        joined_fetch(&join, &join.expected_oid, &handle, &proxy_url, &ca_path),
        &join.expected_oid,
        ExpectedFetch::Present,
    )
    .await;
    write_receipt(
        &join.first_fetch_receipt,
        serde_json::json!({ "oid": join.expected_oid, "git_commands": 1 }),
    );
    let Withdrawal { withdrawn_oid } = loop {
        match std::fs::read(&join.withdrawal_ready) {
            Ok(bytes) => break serde_json::from_slice(&bytes).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("read withdrawal receipt: {error}"),
        }
    };
    assert_ne!(join.expected_oid, withdrawn_oid);
    let (result, present) = fetch_fresh(
        joined_fetch(&join, &withdrawn_oid, &handle, &proxy_url, &ca_path),
        &withdrawn_oid,
        ExpectedFetch::Withdrawn,
    )
    .await;
    write_receipt(
        &join.withdrawn_fetch_receipt,
        serde_json::json!({
            "oid": withdrawn_oid, "git_commands": 1, "exit_code": result.status.code(), "present": present,
        }),
    );
    proxy.abort();
}

fn write_receipt(path: &Path, receipt: serde_json::Value) {
    let mut output = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    serde_json::to_writer(output.as_file_mut(), &receipt).unwrap();
    output.persist(path).unwrap();
}

fn joined_fetch(
    join: &Join,
    oid: &str,
    handle: &str,
    proxy_url: &str,
    ca_path: &Path,
) -> AsyncCommand {
    let launcher = format!(
        "{}\nconst result = require('node:child_process').spawnSync('/usr/bin/git', process.argv.slice(1), {{stdio:'inherit'}}); process.exit(result.status ?? 1);",
        join.git_client_prelude
    );
    let mut command = AsyncCommand::new(&join.node_binary);
    command
        .env_clear()
        .envs(&join.git_environment)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env(GIT_KEY, handle)
        .env("HTTPS_PROXY", proxy_url)
        .env("GIT_SSL_CAINFO", ca_path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .args([
            "-e",
            &launcher,
            "--",
            "fetch",
            "--no-tags",
            &join.git_url,
            oid,
        ]);
    command
}
