// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Terminal external HTTP exchange. The origin socket never receives HTTP bytes.

use futures::FutureExt;
use std::time::SystemTime;

use miette::{IntoDiagnostic, Result, miette};
use openshell_core::proto::{HttpHeader, HttpRequestEvaluation, SupervisorMiddlewarePhase};
use openshell_core::secrets::contains_reserved_credential_marker_bytes;
use openshell_ocsf::ctx::ctx as ocsf_ctx;
use openshell_supervisor_middleware::external_exchange::MAX_HTTP_EXCHANGE_OPERATION_TIME;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    BufferResult, HttpResponseMiddlewareRelay, L7Request, RelayOutcome, RelayRequestOptions,
    buffer_request_body_for_middleware, request_authority, request_has_upgrade_header,
    strip_connection_nominated_headers,
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

    pub(crate) async fn relay(
        self,
        req: &L7Request,
        options: RelayRequestOptions<'_>,
        middleware: HttpResponseMiddlewareRelay<'_>,
    ) -> Result<RelayOutcome> {
        let custody = self
            .custody
            .ok_or_else(|| miette!("protected operation lacks an accepted response stream"))?;
        // Keep complete protected-response custody off the ordinary per-connection future stack.
        Box::pin(relay(req, self.downstream, custody, options, middleware)).await
    }
}

async fn relay<C>(
    req: &L7Request,
    client: &mut C,
    custody: [u8; 32],
    options: RelayRequestOptions<'_>,
    middleware: HttpResponseMiddlewareRelay<'_>,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let now = SystemTime::now();
    let deadline = openshell_core::middleware::http_exchange_operation_horizon(
        &middleware.request_context.request_id,
        now,
    )
    .map_or(now, |horizon| {
        horizon.min(now + MAX_HTTP_EXCHANGE_OPERATION_TIME)
    });
    let operation_end =
        tokio::time::Instant::now() + deadline.duration_since(now).unwrap_or_default();
    let request_id = middleware.request_context.request_id.clone();
    let mut progress = CustodyProgress {
        request_id: &request_id,
        opening_started: false,
        delivery_started: false,
        released: false,
    };
    let mut opening_started_remote = false;
    let policy_name = middleware.policy_name;
    let host = middleware.target.host.clone();
    let port = u16::try_from(middleware.target.port).unwrap_or_default();
    let result = tokio::time::timeout_at(
        operation_end,
        exchange(
            req,
            client,
            options,
            middleware,
            deadline,
            custody,
            &mut progress,
            &mut opening_started_remote,
        ),
    )
    .await;
    if let Ok(Ok(outcome)) = result {
        Ok(outcome)
    } else {
        // No raw authority or provider diagnostics.
        // The business send may already have happened; never retry this exchange.
        use openshell_ocsf::{
            ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
            SeverityId, StatusId, Url, ocsf_emit,
        };
        let event = HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Other)
            .action(if opening_started_remote {
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
            .firewall_rule(policy_name, "external-http-exchange")
            .message(if opening_started_remote {
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
            client.shutdown().await
        }).await;
        Ok(RelayOutcome::Consumed)
    }
}

/// Content-free finite transitions; cancellations and timeouts cannot silently become successful exchanges.
struct CustodyProgress<'a> {
    request_id: &'a str,
    opening_started: bool,
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
        if !self.opening_started {
            self.event("exchange_not_started");
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
async fn exchange<C>(
    req: &L7Request,
    client: &mut C,
    options: RelayRequestOptions<'_>,
    middleware: HttpResponseMiddlewareRelay<'_>,
    deadline: SystemTime,
    custody: [u8; 32],
    progress: &mut CustodyProgress<'_>,
    opening_started_remote: &mut bool,
) -> Result<RelayOutcome>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if middleware.upstream_transport != crate::l7::tls::UpstreamTransport::AuthenticatedTls
        || middleware.target.scheme != "https"
        || options.credential_signing.is_sigv4()
        || options.request_body_credential_rewrite
        || options.mcp_request_validation.is_some()
        || request_has_upgrade_header(&req.raw_header)
    {
        return Err(miette!("unsupported external HTTP exchange"));
    }
    // This bounded seam accepts fixed-length or empty requests only. Reject
    // Expect before the shared buffer can emit an interim 100 response.
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| miette!("exchange request framing invalid"))?;
    let head = std::str::from_utf8(&req.raw_header[..header_end])
        .map_err(|_| miette!("exchange request headers invalid"))?;
    if head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .any(|(name, _)| name.eq_ignore_ascii_case("expect"))
        || matches!(req.body_length, super::BodyLength::Chunked)
        || matches!(req.body_length, super::BodyLength::ContentLength(n)
            if (req.raw_header.len() - header_end) as u64 > n)
    {
        return Err(miette!("unsupported exchange request framing"));
    }
    let guard = options
        .generation_guard
        .ok_or_else(|| miette!("exchange policy guard is missing"))?;
    let connection = middleware
        .exchange_connection
        .ok_or_else(|| miette!("verified exchange connection is missing"))?;
    let proof = connection.proof_for(
        &middleware.target.host,
        u16::try_from(middleware.target.port).map_err(|_| miette!("invalid port"))?,
        guard,
    )?;
    let request_context = middleware.request_context.clone();
    let authority = middleware
        .runner
        .http_exchange_authority(middleware.chain)
        .await?
        .ok_or_else(|| miette!("HTTP exchange authority is missing"))?;
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
    let headers = strip_connection_nominated_headers(&buffered.headers, false)?;
    let raw_query = crate::l7::middleware::raw_query_from_request_headers(&headers)?;
    if contains_reserved_credential_marker_bytes(&buffered.body)
        || contains_reserved_credential_marker_bytes(&headers)
    {
        return Err(miette!(
            "protected operation contains unresolved credential markers"
        ));
    }
    // Deliberately narrow allowlist: workload authentication, routing, custom
    // control and framing headers never cross this seam. Content-Length is not
    // authority input; the service frames the provided body itself.
    let visible: Vec<_> = crate::l7::middleware::safe_middleware_headers(&headers)?
        .visible
        .into_iter()
        .filter(|(name, _)| matches!(name.as_str(), "accept" | "content-type"))
        .collect();
    let mut target = middleware.target.clone();
    target.query = raw_query;
    guard.ensure_current()?;
    let mut extra = [0; 1];
    let dispatch = async {
        guard.ensure_current()?;
        *opening_started_remote = true;
        progress.opening_started = true;
        progress.event("exchange_started");
        let approved = authority
            .exchange(
                HttpRequestEvaluation {
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    context: Some(request_context),
                    config: None,
                    target: Some(target),
                    headers: visible
                        .into_iter()
                        .map(|(name, value)| HttpHeader { name, value })
                        .collect(),
                    body: buffered.body,
                    middleware_name: String::new(),
                },
                deadline,
                &custody,
                proof,
            )
            .await?;
        if approved.body.len() > response_limit {
            return Err(miette!("exchange response exceeds capacity"));
        }
        // Fixed local framing; the service cannot inject headers or choose a
        // downstream destination. HEAD is represented with an empty body.
        if req.action == "HEAD" && !approved.body.is_empty() {
            return Err(miette!("exchange HEAD body invalid"));
        }
        let length = if matches!(approved.status, 204 | 304) {
            String::new()
        } else {
            format!("Content-Length: {}\r\n", approved.body.len())
        };
        let mut response = format!(
            "HTTP/1.1 {} Response\r\nContent-Type: {}\r\n{length}Connection: close\r\n\r\n",
            approved.status, approved.content_type,
        )
        .into_bytes();
        response.extend_from_slice(&approved.body);
        Ok(response)
    };
    let response = tokio::select! {
        biased;
        // After the request is complete, EOF, error or a pipelined request all revoke this
        // pending sender. Dropping the exchange cancels it; there is no replacement destination.
        _ = client.read(&mut extra) => return Err(miette!("accepted response stream closed or changed")),
        _ = guard.wait_until_stale() => return Err(miette!("exchange generation changed")),
        result = dispatch => result?,
    };

    // Repoll the actual sink at the release boundary, never resolve a destination from wire data.
    if client.read(&mut extra).now_or_never().is_some() {
        return Err(miette!("accepted response stream no longer live"));
    }
    guard.ensure_current()?;
    progress.delivery_started = true;
    tokio::select! {
        biased;
        _ = guard.wait_until_stale() => return Err(miette!("exchange generation changed during delivery")),
        result = async {
            client.write_all(&response).await?;
            client.flush().await?;
            client.shutdown().await
        } => result.into_diagnostic()?,
    }
    progress.event("response_released");
    progress.released = true;
    // One protected operation per connection; another operation must capture
    // again. No redirect handling, retry or upgrade can reuse this exchange.
    Ok(RelayOutcome::Consumed)
}

#[cfg(test)]
#[path = "external_exchange_tests.rs"]
mod tests;
