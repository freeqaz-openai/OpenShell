// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-memory gateway with real launch credentials for the supervisor wire test.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::grpc_client::{GatewayCredentials, GatewayEndpoint};
use openshell_core::proto::{
    ImportProviderProfilesRequest, Provider, ProviderProfile, ProviderProfileImportItem, Sandbox,
    SandboxPhase, SandboxPolicy, SandboxSpec, SandboxStatus, datamodel::v1::ObjectMeta,
    open_shell_server::OpenShell, workspace_selector,
};
use prost::Message;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use crate::auth::sandbox_jwt::{ExtensionJwtIssuer, SandboxSessionJwtAuthority};
use crate::auth::sandbox_session::PersistedSandboxIdentity;
use crate::config_file::ProviderAssertionRegistration;
use crate::persistence::{ObjectType, WriteCondition};
use crate::{ConnectionSource, MultiplexService, OpenShellService, Store};

pub const SANDBOX: &str = "wire-sandbox";
pub const SIBLING: &str = "wire-sibling";
pub const PROVIDER: &str = "wire-provider";
pub const PROVIDER_ID: &str = "wire-provider-id";
pub const UNREGISTERED_PROVIDER: &str = "wire-unregistered";
const GATEWAY: &str = "wire-gateway";

pub struct ProviderGrantGateway {
    pub sandbox: GatewayEndpoint,
    pub sibling: GatewayEndpoint,
    accept_loop: JoinHandle<()>,
}

impl Drop for ProviderGrantGateway {
    fn drop(&mut self) {
        self.accept_loop.abort();
    }
}

impl ProviderGrantGateway {
    pub async fn start(
        tls: tokio_rustls::TlsAcceptor,
        profile: ProviderProfile,
        credential_key: &str,
        endpoint: &str,
        environment: &[(&str, &str)],
    ) -> Self {
        let mut state = super::gateway_state_with_driver("test").await;
        let key = openshell_bootstrap::jwt::generate_jwt_key().expect("test signing key");
        let authority = Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                key.signing_key_pem.as_bytes(),
                key.public_key_pem.as_bytes(),
                key.kid.clone(),
                GATEWAY,
                Some(Duration::from_secs(900)),
            )
            .expect("session authority"),
        );
        let assertion_issuer = ExtensionJwtIssuer::from_pem(
            key.signing_key_pem.as_bytes(),
            key.public_key_pem.as_bytes(),
            key.kid.clone(),
            GATEWAY,
            Duration::from_secs(300),
        )
        .expect("assertion issuer");
        state.sandbox_session_jwt_authority = Some(authority.clone());
        state.extension_jwt_issuer = Some(Arc::new(assertion_issuer));
        state.provider_assertions = vec![ProviderAssertionRegistration {
            provider_id: PROVIDER_ID.into(),
            credential_key: credential_key.into(),
            token_endpoint: endpoint.into(),
        }];

        let state = Arc::new(state);
        let profile_id = profile.id.clone();
        let request = super::authenticate_as_dev_user(tonic::Request::new(()))
            .expect("fixture user")
            .map(|()| ImportProviderProfilesRequest {
                profiles: vec![ProviderProfileImportItem {
                    profile: Some(profile),
                    source: "provider-grant-wire.yaml".into(),
                }],
                workspace_scope: Some(workspace_selector("default")),
                ..Default::default()
            });
        let imported = OpenShellService::new(state.clone())
            .import_provider_profiles(request)
            .await
            .expect("import test provider profile")
            .into_inner();
        assert!(
            imported.imported,
            "fixture profile: {:?}",
            imported.diagnostics
        );

        for (name, id) in [
            (PROVIDER, PROVIDER_ID),
            (UNREGISTERED_PROVIDER, "wire-unregistered-id"),
        ] {
            persist(
                &state.store,
                name,
                id,
                Provider {
                    metadata: Some(metadata(name, id)),
                    r#type: profile_id.clone(),
                    profile_workspace: "default".into(),
                    credentials: environment
                        .iter()
                        .map(|(name, value)| ((*name).into(), (*value).into()))
                        .collect(),
                    ..Default::default()
                },
            )
            .await;
        }
        let sandbox_credentials =
            persist_sandbox(&state.store, &authority, SANDBOX, PROVIDER).await;
        let sibling_credentials =
            persist_sandbox(&state.store, &authority, SIBLING, UNREGISTERED_PROVIDER).await;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("gateway bind");
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let service = MultiplexService::new(state);
        let accept_loop = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted.expect("gateway accept");
                        openshell_core::net::set_tcp_nodelay_best_effort(&stream);
                        let service = service.clone();
                        let tls = tls.clone();
                        connections.spawn(async move {
                            let stream = tls.accept(stream).await.expect("gateway TLS");
                            service.serve(stream, ConnectionSource::Peer(peer)).await
                        });
                    }
                    completed = connections.join_next(), if !connections.is_empty() => {
                        // HTTP/2 clients can drop a connection without a graceful close.
                        let _ = completed.expect("gateway connection").expect("gateway task");
                    }
                }
            }
        });

        Self {
            sandbox: GatewayEndpoint::new(url.clone(), sandbox_credentials),
            sibling: GatewayEndpoint::new(url, sibling_credentials),
            accept_loop,
        }
    }
}

fn metadata(name: &str, id: &str) -> ObjectMeta {
    ObjectMeta {
        id: id.into(),
        name: name.into(),
        workspace: "default".into(),
        ..Default::default()
    }
}

async fn persist_sandbox(
    store: &Store,
    authority: &SandboxSessionJwtAuthority,
    sandbox_id: &str,
    provider: &str,
) -> GatewayCredentials {
    let identity = PersistedSandboxIdentity::new().expect("test runtime identity");
    let mut metadata = metadata(sandbox_id, sandbox_id);
    identity.write(&mut metadata.annotations);
    persist(
        store,
        sandbox_id,
        sandbox_id,
        Sandbox {
            metadata: Some(metadata),
            spec: Some(SandboxSpec {
                providers: vec![provider.into()],
                policy: Some(SandboxPolicy::default()),
                ..Default::default()
            }),
            status: Some(SandboxStatus {
                phase: SandboxPhase::Provisioning as i32,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;
    let auth = authority
        .mint_persisted_launch(sandbox_id, &identity)
        .expect("mint test launch");
    GatewayCredentials::from_auth_bundle(&auth.supervisor).expect("test launch credentials")
}

async fn persist<T: Message + ObjectType>(store: &Store, name: &str, id: &str, message: T) {
    store
        .put_if(
            T::object_type(),
            id,
            name,
            "default",
            &message.encode_to_vec(),
            None,
            WriteCondition::MustCreate,
        )
        .await
        .expect("persist test record");
}
