<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Supervisor network

This crate owns egress proxying, TLS interception, L7 policy, and credential
injection. Operator configuration and protocol details are documented in
[supervisor middleware operations](../../docs/extensibility/supervisor-middleware/operations.mdx).

## External STATIC credential flow

A protected middleware entry selects one authenticated authority, one literal
host, and fail-closed behavior. A fresh `execution_authority: true` policy
explicitly shares mediated HTTPS access among processes inside the workload.
The supervisor requires a verified blocked workload connect and binds the hash
of the admitted typed policy to the operation. An existing executable-pin
policy still requires its exact connecting leaf and uses a separate profile.
Changing to execution-wide authority requires an explicit new grant.

Only `preauthorize_transparent_open` can produce the private admission token.
It receives the trusted backend’s blocked connect, seccomp thread identity,
destination and completion decision on the stream that becomes the relay.
The supervisor verifies the upstream TLS certificate and captures exclusive
custody of the actual workload response stream at REST acceptance. It then
applies request middleware and strips incoming credential and control fields,
including every workload-supplied `X-` header in this prototype. It then
opens one authenticated bidirectional installation exchange. See
[installation enrollment and custody](../openshell-supervisor-process/README.md).

The authority must both support and require the selected enforcement profile.
For execution-wide authority, the ordered capabilities are
`http-credential-access.v1`, `installation-exchange.v1`, `response-custody.v1`,
`execution-authority.v1` and `protected-no-material.v1`, all under
`openshell.supervisor-middleware.`. The authority may expressly select no
material for the admitted operation. That selection injects no credentials,
requires a matching send permit and uses the same complete response policy.
Absent or unusable credentials never select this path. The older verified
connector profile requires credential material.
The supervisor signs the exact resolve request and fresh stream challenge with
its enrolled key. Before the first origin write, it checks the fresh send
permit against the captured custody, material, operation, local policy
generation and authorized start time. An observed closed peer revokes a
pending send; a failed or uncertain dispatch is terminal.

The supervisor reads the bounded response through its final trailer, submits
the complete status, safe headers, decoded body and trailers on that same
exchange, and waits for explicit approval and successful terminal status.
It frames the approved result locally, checks for literal selected-material
echoes, and writes only to the stream it still owns. The original 30-second
operation horizon and 4 MiB staged limit also apply to finite event streams.
Provider semantics and the two independent, current authorization decisions
belong to the external authority. Revocation can still race a send in progress.

## Verification

```shell
cargo test -p openshell-supervisor-network l7::rest::credentials::tests
cargo test -p openshell-supervisor-middleware
cargo test -p openshell-policy
```

The focused relay tests use a real TLS/gRPC authority with Ed25519 JWT validation
and a certificate-verified TLS provider. Transparent admission tests use genuine
`ProcfsIdentityResolver` results as synthetic trusted backend inputs, then pass the
actual admitted tuple to the common relay. They do not install seccomp or exercise
the broker registry. Explicit CONNECT is tested as a denial. Relay regressions use a
raw TCP provider to verify zero authority calls and zero credential bytes for
plaintext, including requests whose target claims HTTPS. Positive TLS, failed
handshake, ordinary HTTP, and encoded response-reason cases exercise the same
adapter. They check actual bytes sent, concurrent operation isolation,
revocation between checks, unavailable authority, malformed and expired permits,
and response denial/credential echoes. They establish component transport
behavior, not external IAM, a deployed sandbox, provider access, or bypass
prevention. Installed sandbox e2e coverage remains required before enabling an
integration that depends on those properties.

## Loaded enforcement

`OpaEngine::loaded_enforcement_evidence` inspects the installed policy and registry
under the generation guard returned by loading. It rejects quarantined or stale
generations and cached manifests without authenticated credential/response bindings.
Startup and successful configuration reconciliation report that evidence using the
existing admission registration fence. The gateway validates the sender and exact
current tuple, persists the observation, and revalidates it on policy-status reads.
Old protobuf parsers and old cached manifests cannot qualify from `LOADED` alone.
The supervisor declares implementation support on configuration fetches. A gateway
withholds protected policy bytes from sandbox callers without that declaration,
using the existing configuration-error response. This delivery gate is independent
of the post-installation evidence. Initial support targets fresh matching installs;
mixed-version hot activation remains an installed qualification gate.

Consumers revalidate the receipt against their admitted configuration and the
gateway-validated registered-instance claim in the extension JWT. Startup and poll
clients pass their own registration UUID; the gateway rejects stale requests rather
than substituting the current registration. This is not process attestation or a
lease. Protected request UUIDv7 creation fixes the 30-second replay horizon before
resolution. Installed containment and exclusion of Agent access to supervisor
credentials remain qualification gates.
