// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded HTTPS forwarding with an exclusive external STATIC authority.

use futures::FutureExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;

use miette::{IntoDiagnostic, Result, miette};
use openshell_core::proto::{HttpHeader, HttpRequestEvaluation, SupervisorMiddlewarePhase};
use openshell_core::secrets::contains_reserved_credential_marker_bytes;
use openshell_ocsf::ctx::ctx as ocsf_ctx;
use openshell_supervisor_middleware::credentials::{
    MAX_CREDENTIAL_OPERATION_TIME, is_credential_header,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::{
    BufferResult, EndpointObserver, HttpResponseMiddlewareRelay, L7Request, ObservedUpstream,
    RelayOutcome, RelayRequestOptions, buffer_request_body_for_middleware,
    http_response::{capture_custody_response, frame_custody_response},
    rebuild_request_with_buffered_body, request_authority, request_has_upgrade_header,
    strip_connection_nominated_headers, strip_header,
};

const MAX_PROTECTED_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The actual accepted response stream. Neither the stream nor its custody can be replaced.
pub struct AcceptedResponseSink<'a, C> {
    downstream: &'a mut C,
    custody: Option<[u8; 32]>,
}

impl<'a, C: AsyncRead + AsyncWrite + Unpin> AcceptedResponseSink<'a, C> {
    /// Called at REST acceptance, before parsing, middleware admission, or consulting current policy.
    /// Ordinary connections generate no custody. They cannot become protected on a later policy change.
    pub(crate) fn capture(downstream: &'a mut C, verified_connection: bool) -> Result<Self> {
        let custody = verified_connection
            .then(openshell_extension_core::new_response_custody)
            .transpose()
            .map_err(|_| miette!("unable to capture protected response custody"))?;
        Ok(Self {
            downstream,
            custody,
        })
    }

    /// Local parsing and pre-credential middleware use this same stream, never a lookup by public ID.
    pub(crate) fn client(&mut self) -> &mut C {
        self.downstream
    }

    pub(crate) async fn relay<U: AsyncRead + AsyncWrite + Unpin>(
        self,
        req: &L7Request,
        upstream: &mut U,
        options: RelayRequestOptions<'_>,
        middleware: HttpResponseMiddlewareRelay<'_>,
        observer: Option<&EndpointObserver>,
    ) -> Result<RelayOutcome> {
        let custody = self
            .custody
            .ok_or_else(|| miette!("protected operation lacks an accepted response stream"))?;
        // Keep complete protected-response custody off the ordinary per-connection future stack.
        Box::pin(relay(
            req,
            self.downstream,
            custody,
            upstream,
            options,
            middleware,
            observer,
        ))
        .await
    }
}

async fn relay<C, U>(
    req: &L7Request,
    client: &mut C,
    custody: [u8; 32],
    upstream: &mut U,
    options: RelayRequestOptions<'_>,
    middleware: HttpResponseMiddlewareRelay<'_>,
    observer: Option<&EndpointObserver>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let now = SystemTime::now();
    let deadline = openshell_core::middleware::http_credential_operation_horizon(
        &middleware.request_context.request_id,
        now,
    )
    .map_or(now, |horizon| {
        horizon.min(now + MAX_CREDENTIAL_OPERATION_TIME)
    });
    let operation_end =
        tokio::time::Instant::now() + deadline.duration_since(now).unwrap_or_default();
    let upstream = &mut ObservedUpstream { upstream, observer };
    let request_id = middleware.request_context.request_id.clone();
    let mut progress = CustodyProgress {
        request_id: &request_id,
        permit_accepted: false,
        delivery_started: false,
        released: false,
    };
    let mut dispatch_started = false;
    let policy_name = middleware.policy_name;
    let host = middleware.target.host.clone();
    let port = u16::try_from(middleware.target.port).unwrap_or_default();
    let result = tokio::time::timeout_at(
        operation_end,
        exchange(
            req,
            client,
            upstream,
            options,
            middleware,
            observer,
            deadline,
            custody,
            &mut progress,
            &mut dispatch_started,
        ),
    )
    .await;
    if let Ok(Ok(outcome)) = result {
        Ok(outcome)
    } else {
        // No raw authority, provider, selected material, or evidence diagnostics.
        // The business send may already have happened; never retry this exchange.
        use openshell_ocsf::{
            ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
            SeverityId, StatusId, Url, ocsf_emit,
        };
        let event = HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Other)
            .action(if dispatch_started {
                ActionId::Other
            } else {
                ActionId::Denied
            })
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .http_request(HttpRequest::new(
                &req.action,
                // The target can contain private credential references even on an early refusal.
                Url {
                    scheme: Some("https".into()),
                    hostname: Some(host.clone()),
                    port: Some(port),
                    path: None,
                },
            ))
            .dst_endpoint(Endpoint::from_domain(&host, port))
            .firewall_rule(policy_name, "credential-authority")
            .message(if dispatch_started {
                "Protected HTTP exchange failed after possible dispatch"
            } else {
                "Protected HTTP exchange refused before dispatch"
            })
            .build();
        ocsf_emit!(event);
        // Cleanup cannot extend the operation or stall on a non-reading peer.
        // Consumed tells the owning relay to close even if cleanup times out.
        let _ = tokio::time::timeout_at(operation_end, async {
            if !progress.delivery_started {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                client.flush().await?;
            }
            client.shutdown().await?;
            upstream.shutdown().await
        }).await;
        Ok(RelayOutcome::Consumed)
    }
}

/// Content-free finite transitions; cancellations and timeouts cannot silently become permits.
struct CustodyProgress<'a> {
    request_id: &'a str,
    permit_accepted: bool,
    delivery_started: bool,
    released: bool,
}

impl CustodyProgress<'_> {
    fn event(&self, response_custody_event: &'static str) {
        if uuid::Uuid::parse_str(self.request_id)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == self.request_id)
        {
            tracing::info!(
                request_id = self.request_id,
                response_custody_event,
                "Protected response custody transition"
            );
        }
    }
}

impl Drop for CustodyProgress<'_> {
    fn drop(&mut self) {
        if !self.permit_accepted {
            self.event("no_permit");
        }
        if !self.released {
            self.event(if self.delivery_started {
                "response_delivery_incomplete"
            } else {
                "response_blocked"
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange<C, U>(
    req: &L7Request,
    client: &mut C,
    upstream: &mut U,
    options: RelayRequestOptions<'_>,
    middleware: HttpResponseMiddlewareRelay<'_>,
    observer: Option<&EndpointObserver>,
    deadline: SystemTime,
    custody: [u8; 32],
    progress: &mut CustodyProgress<'_>,
    dispatch_started: &mut bool,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    if middleware.upstream_transport != crate::l7::tls::UpstreamTransport::AuthenticatedTls
        || middleware.target.scheme != "https"
        || options.credential_signing.is_sigv4()
        || options.request_body_credential_rewrite
        || options.mcp_request_validation.is_some()
        || request_has_upgrade_header(&req.raw_header)
    {
        return Err(miette!("unsupported protected credential operation"));
    }
    let guard = options
        .generation_guard
        .ok_or_else(|| miette!("credential policy guard is missing"))?;
    let connection = middleware
        .credential_connection
        .ok_or_else(|| miette!("verified credential connection is missing"))?;
    let proof = connection.proof_for(
        &middleware.target.host,
        u16::try_from(middleware.target.port).map_err(|_| miette!("invalid port"))?,
        guard,
    )?;
    let request_context = middleware.request_context.clone();
    let authority = middleware
        .runner
        .credential_authority(middleware.chain)
        .await?
        .ok_or_else(|| miette!("credential authority is missing"))?;
    let _admission = middleware
        .runner
        .reserve_middleware_work_admission()
        .await?;
    let host = request_authority(&req.raw_header, Some(443))?
        .ok_or_else(|| miette!("protected request authority is missing"))?;
    if !host
        .authority
        .host()
        .eq_ignore_ascii_case(&middleware.target.host)
        || u32::from(host.effective_port) != middleware.target.port
    {
        return Err(miette!("protected request authority mismatch"));
    }
    let response_limit = authority
        .max_payload_bytes()
        .min(MAX_PROTECTED_RESPONSE_BYTES);
    let buffered = match buffer_request_body_for_middleware(
        req,
        client,
        options.generation_guard,
        authority.max_payload_bytes(),
    )
    .await?
    {
        BufferResult::Buffered(buffered) => buffered,
        BufferResult::OverCapacity { .. } => {
            return Err(miette!("protected request exceeds capacity"));
        }
    };
    let mut headers = strip_connection_nominated_headers(&buffered.headers, false)?;
    let raw_query = crate::l7::middleware::raw_query_from_request_headers(&headers)?;
    // Execution/control authentication is never provider authentication. Drop
    // every supported credential field, not merely the one selected for injection.
    // To keep operator-specific control headers out of both the authority input
    // and the provider request, this prototype strips all workload-supplied X- headers.
    let names: Vec<String> = std::str::from_utf8(&headers)
        .map_err(|_| miette!("invalid protected headers"))?
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.to_ascii_lowercase())
        .filter(|name| {
            is_credential_header(name)
                || matches!(name.as_str(), "cookie" | "set-cookie" | "forwarded")
                || name.starts_with("proxy-")
                || name.starts_with("x-")
        })
        .collect();
    for name in names {
        headers = strip_header(&headers, &name)?;
    }
    if contains_reserved_credential_marker_bytes(&buffered.body)
        || contains_reserved_credential_marker_bytes(&headers)
    {
        return Err(miette!(
            "protected operation contains unresolved credential markers"
        ));
    }
    let visible = crate::l7::middleware::safe_middleware_headers(&headers)?.visible;
    let mut target = middleware.target.clone();
    target.query = raw_query;
    guard.ensure_current()?;
    let mut extra = [0; 1];
    let dispatch = async {
        let selection = match authority
            .resolve(
                HttpRequestEvaluation {
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    context: Some(request_context),
                    config: None,
                    target: Some(target),
                    headers: visible
                        .into_iter()
                        .map(|(name, value)| HttpHeader { name, value })
                        .collect(),
                    body: buffered.body.clone(),
                    middleware_name: String::new(),
                },
                deadline,
                &custody,
                proof,
            )
            .await
        {
            Ok(selection) => {
                progress.event(if selection.no_material_required() {
                    "resolve_no_material_accepted"
                } else {
                    "resolve_accepted"
                });
                selection
            }
            Err(err) => {
                progress.event("resolve_refused");
                return Err(err);
            }
        };

        // Complete every transform before the final online authorization. The final
        // permit cannot authorize a different body, destination, header or material.
        let rebuilt = rebuild_request_with_buffered_body(req, &headers, &buffered.body, &[])?;
        let header_end = rebuilt
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| miette!("protected request framing invalid"))?
            + 4;
        let mut outgoing = Zeroizing::new(rebuilt.raw_header[..header_end - 2].to_vec());
        let mut secret_needles = Vec::new();
        for header in selection.headers() {
            if !is_credential_header(&header.name) {
                return Err(miette!("invalid credential header"));
            }
            outgoing.extend_from_slice(header.name.as_bytes());
            outgoing.extend_from_slice(b": ");
            outgoing.extend_from_slice(header.value.as_bytes());
            outgoing.extend_from_slice(b"\r\n");
            secret_needles.push(Zeroizing::new(header.value.as_bytes().to_vec()));
            if header.name == "authorization"
                && let Some((_, token)) = header.value.split_once(' ')
                && !token.is_empty()
            {
                secret_needles.push(Zeroizing::new(token.as_bytes().to_vec()));
            }
        }
        outgoing.extend_from_slice(b"\r\n");
        outgoing.extend_from_slice(&buffered.body);
        guard.ensure_current()?;
        let no_material = selection.no_material_required();
        let permit = selection.authorize_send(&custody).await?;
        progress.event(if no_material {
            "permit_no_material_accepted"
        } else {
            "permit_accepted"
        });
        progress.permit_accepted = true;
        let mut status_line = String::new();
        let start_by = permit.send_start_by();
        let approved = permit
            .dispatch_and_protect(&custody, async {
                guard.ensure_current()?;
                let start_window = start_by
                    .duration_since(SystemTime::now())
                    .map_err(|_| miette!("send start expired"))?;
                *dispatch_started = true;
                let first = tokio::time::timeout(start_window, upstream.write(&outgoing))
                    .await
                    .map_err(|_| miette!("send start expired"))?
                    .into_diagnostic()?;
                if first == 0 {
                    return Err(miette!("protected send made no progress"));
                }
                upstream
                    .write_all(&outgoing[first..])
                    .await
                    .into_diagnostic()?;
                upstream.flush().await.into_diagnostic()?;
                let (status, captured) =
                    capture_custody_response(upstream, &req.action, response_limit, observer)
                        .await?;
                status_line = status;
                Ok(captured)
            })
            .await?;
        let mut response = ProtectedResponse::default();
        frame_custody_response(&status_line, approved, &mut response).await?;
        if secret_needles.iter().any(|secret| {
            response
                .bytes
                .windows(secret.len())
                .any(|w| w == secret.as_slice())
        }) {
            return Err(miette!("protected response contains selected material"));
        }
        Ok(response)
    };
    let response = tokio::select! {
        biased;
        // After the request is complete, EOF, error or a pipelined request all revoke this
        // pending sender. Dropping the exchange cancels it; there is no replacement destination.
        _ = client.read(&mut extra) => return Err(miette!("accepted response stream closed or changed")),
        result = dispatch => result?,
    };

    // Repoll the actual sink at the release boundary, never resolve a destination from wire data.
    if client.read(&mut extra).now_or_never().is_some() {
        return Err(miette!("accepted response stream no longer live"));
    }
    guard.ensure_current()?;
    progress.delivery_started = true;
    client.write_all(&response.bytes).await.into_diagnostic()?;
    client.flush().await.into_diagnostic()?;
    client.shutdown().await.into_diagnostic()?;
    progress.event("response_released");
    progress.released = true;
    // One protected operation per connection; another operation must capture
    // again. No redirect handling, retry or upgrade can reuse this permit.
    Ok(RelayOutcome::Consumed)
}

#[cfg(test)]
#[path = "static_credentials_tests.rs"]
mod tests;

#[derive(Default)]
struct ProtectedResponse {
    bytes: Zeroizing<Vec<u8>>,
}

impl AsyncWrite for ProtectedResponse {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if bytes.len() > MAX_PROTECTED_RESPONSE_BYTES.saturating_sub(self.bytes.len()) {
            return Poll::Ready(Err(std::io::Error::other(
                "protected response exceeds capacity",
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
