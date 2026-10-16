// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    AcceptedProxyConnection, Arc, BinaryIdentityCache, DenialEvent, DestinationRequest,
    EgressIntent, IpAddr, MappingLookupError, NetworkAction, NetworkOpenTimingGuard, OpaEngine,
    PendingTcpOpen, ResolvedEndpointStore, SuppliedIdentityDenial, SuppliedIdentityError,
    TcpOpenDecision, TcpOpenDenial, TransparentOpen, TransparentTarget,
    authorize_supplied_identity_inner, emit_denial_simple, emit_staged_transparent_denial,
    hydrate_destination_plan, is_always_blocked_ip, mpsc, pinned_transparent_plan,
    resolve_transparent_target, validate_destination, warn,
};

/// Mint authority confined to admission of the backend's blocked connect.
/// Neither an explicit listener identity nor a later procfs lookup can construct it.
pub struct VerifiedTransparentConnect {
    _private: (),
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn preauthorize_transparent_open(
    connection: PendingTcpOpen,
    policy_dns_store: Option<&Arc<ResolvedEndpointStore>>,
    opa_engine: &OpaEngine,
    identity_cache: &BinaryIdentityCache,
    backend_host_gateway: Option<IpAddr>,
    trusted_host_gateway: Option<IpAddr>,
    has_policy_local: bool,
    denial_tx: Option<&mpsc::UnboundedSender<DenialEvent>>,
) -> Option<AcceptedProxyConnection> {
    let PendingTcpOpen {
        stream,
        binary_identity,
        destination,
        socket: _,
        policy_generation: _,
        timing,
        decision: completion,
    } = connection;
    let _timing = NetworkOpenTimingGuard {
        timing,
        operation: "tcp",
    };
    if destination.ip() == IpAddr::V4(crate::policy_dns::POLICY_LOCAL_ADDRESS) {
        if destination.port() != 80 || !has_policy_local {
            emit_staged_transparent_denial(
                destination,
                None,
                &binary_identity,
                "sandbox-local policy API requires port 80 and an active context",
                "transparent_tcp_policy_local_invalid_destination",
            );
            let _ = completion.send(TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination));
            return None;
        }
        let identity_check = binary_identity
            .as_ref()
            .map_err(|_| TcpOpenDenial::IdentityUnavailable)
            .and_then(|identity| {
                identity_cache
                    .verify_or_cache_supplied_identity(identity)
                    .map_err(|error| match error {
                        SuppliedIdentityError::Unavailable(_) => TcpOpenDenial::IdentityUnavailable,
                        SuppliedIdentityError::CapacityExhausted => {
                            TcpOpenDenial::ResourceExhausted
                        }
                    })
            });
        if let Err(denial) = identity_check {
            emit_staged_transparent_denial(
                destination,
                None,
                &binary_identity,
                "sandbox-local policy API requires a verified workload identity",
                "transparent_tcp_policy_local_identity_unavailable",
            );
            let _ = completion.send(TcpOpenDecision::Denied(denial));
            return None;
        }
        if completion.send(TcpOpenDecision::RelayReady).is_err() {
            return None;
        }
        return Some((
            stream,
            Some(binary_identity),
            None,
            Some(TransparentOpen {
                destination,
                authorization: None,
            }),
        ));
    }
    let TransparentTarget { host, intent } =
        match resolve_transparent_target(destination, policy_dns_store, opa_engine) {
            Ok(target) => target,
            Err(error) => {
                warn!(%destination, %error, "Denied staged transparent connection");
                emit_staged_transparent_denial(
                    destination,
                    None,
                    &binary_identity,
                    &error.to_string(),
                    "transparent_tcp_mapping_denied",
                );
                let _ = completion.send(TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination));
                return None;
            }
        };
    let mapped_host = intent.is_some().then_some(host.as_str());
    let supplied_authorization = authorize_supplied_identity_inner(
        opa_engine,
        identity_cache,
        EgressIntent::connect(host.clone(), destination.port()),
        &binary_identity,
        Some(&VerifiedTransparentConnect { _private: () }),
    );
    let mut decision = supplied_authorization.decision;
    if let NetworkAction::Deny { reason } = &decision.action {
        let (denial, status_detail) = supplied_authorization.denial.map_or(
            (TcpOpenDenial::PolicyDenied, "transparent_tcp_policy_denied"),
            |denial| match denial {
                SuppliedIdentityDenial::IdentityUnavailable => (
                    TcpOpenDenial::IdentityUnavailable,
                    "transparent_tcp_identity_unavailable",
                ),
                SuppliedIdentityDenial::ResourceExhausted => (
                    TcpOpenDenial::ResourceExhausted,
                    "transparent_tcp_resource_exhausted",
                ),
            },
        );
        warn!(%destination, %reason, "Denied staged transparent connection");
        emit_staged_transparent_denial(
            destination,
            mapped_host,
            &binary_identity,
            reason,
            status_detail,
        );
        if supplied_authorization.denial.is_none()
            && !is_always_blocked_ip(destination.ip())
            && let Some(binary) = decision.binary.as_ref()
        {
            emit_denial_simple(
                denial_tx,
                &host,
                destination.port(),
                &binary.to_string_lossy(),
                &decision,
                reason,
                "transparent_tcp_connect",
            );
        }
        let _ = completion.send(TcpOpenDecision::Denied(denial));
        return None;
    }
    // A synthetic destination may dial only the addresses pinned for the
    // generation that produced this decision. Re-acquiring the mapping at that
    // generation keeps a policy reload between correlation and authorization
    // from falling back to resolving the name again. Observation records pin
    // no addresses, so they never reach an upstream dial.
    let pinned_plan = match &intent {
        None => None,
        Some(intent) => match policy_dns_store
            .ok_or(MappingLookupError::Missing)
            .and_then(|store| pinned_transparent_plan(store, destination, &decision))
        {
            Ok(plan) => Some(plan),
            Err(error) => {
                let (reason, status_detail) = match error {
                    _ if intent.record.is_observation() => (
                        "unapproved DNS observation cannot authorize egress".to_string(),
                        "transparent_tcp_observation_denied",
                    ),
                    MappingLookupError::InvalidMapping => (
                        "policy DNS produced an invalid pinned destination".to_string(),
                        "transparent_tcp_destination_denied",
                    ),
                    error => (
                        format!("transparent destination mapping is unavailable: {error}"),
                        "transparent_tcp_mapping_denied",
                    ),
                };
                warn!(%destination, %reason, "Denied staged transparent connection");
                emit_staged_transparent_denial(
                    destination,
                    mapped_host,
                    &binary_identity,
                    &reason,
                    status_detail,
                );
                let _ = completion.send(TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination));
                return None;
            }
        },
    };
    if let Err(denial) =
        hydrate_destination_plan(&mut decision, backend_host_gateway, trusted_host_gateway)
    {
        warn!(%destination, reason = %denial.reason, "Denied staged transparent destination");
        emit_staged_transparent_denial(
            destination,
            mapped_host,
            &binary_identity,
            &denial.reason,
            "transparent_tcp_destination_denied",
        );
        let _ = completion.send(TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination));
        return None;
    }
    if let Some(plan) = pinned_plan {
        decision.endpoint.destination = Some(plan);
    }
    let plan = decision
        .endpoint
        .destination
        .as_ref()
        .expect("destination plan hydrated");
    let connector = match validate_destination(DestinationRequest {
        host: &host,
        port: destination.port(),
        sandbox_entrypoint_pid: 0,
        plan,
    })
    .await
    {
        Ok(connector) => connector,
        Err(denial) => {
            warn!(%destination, reason = %denial.reason, "Denied staged transparent destination");
            emit_staged_transparent_denial(
                destination,
                mapped_host,
                &binary_identity,
                &denial.reason,
                "transparent_tcp_destination_denied",
            );
            let _ = completion.send(TcpOpenDecision::Denied(TcpOpenDenial::InvalidDestination));
            return None;
        }
    };
    if completion.send(TcpOpenDecision::RelayReady).is_err() {
        return None;
    }
    Some((
        stream,
        Some(binary_identity),
        None,
        Some(TransparentOpen {
            destination,
            authorization: Some((decision, connector)),
        }),
    ))
}
