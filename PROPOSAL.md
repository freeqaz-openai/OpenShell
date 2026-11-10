# Gateway-signed assertions for provider token grants

## Decision

Let a provider opt into OAuth client credentials using a short-lived JWT minted by the OpenShell Gateway. Keep SPIFFE as the default and preserve the existing token-exchange flow. Only the supervisor contacts the token endpoint. It injects the access token on admitted traffic. A grant-only profile can do this without an environment placeholder.

## Implementation

1. The operator registers the permitted provider, credential key and exact HTTPS token endpoint. A provider profile selects the new grant mode. A profile alone cannot establish trust in a new recipient.
2. The supervisor requests an assertion through its authenticated Gateway session. The Gateway resolves the attached provider and current profile, checks the registration and mints a dedicated assertion addressed to that endpoint. The broker verifies the signature, issuer, audience, expiry and sandbox/provider binding.
3. The supervisor uses the existing OAuth client and header injection path. An unsupported mode or refused mint fails the request. Keep the new mode disabled during mixed-version upgrades until participating readers support it.

## Local acceptance before EKS

- Run existing SPIFFE and token-exchange regression cases.
- Exercise the new normal supervisor path without a SPIFFE socket, using synthetic identities, a test Gateway and a local HTTPS broker. Verify the broker receives a valid assertion, issues a test access token, and the token reaches the intended upstream request. Verify that neither the assertion nor the issued token reaches the workload. If the fixture supplies a placeholder, verify its replacement on the upstream request. Record which boundaries the test actually exercises.
- Verify an unbound provider, wrong sandbox, unregistered recipient, wrong audience and expired assertion are refused at the owning boundary. Distinguish rejection before a request reaches the broker from rejection by the broker.
- Check generated API bindings, formatting, compilation and independent review. Record any untested integration or known limitations alongside the patch.

## Delivery

Publish a proposal branch on the existing fork for upstream discussion. Keep EKS promotion separate. Before enabling this mode there, qualify the intended broker with the built Gateway and supervisor on a disposable local installation and verify model and Git behavior through the same Agent.

## Reproduce the wire check locally

From the repository root, run:

```sh
cargo test --locked -p openshell-supervisor-network --lib provider_client_assertion_wire
```

The test starts a loopback TLS Gateway and OAuth broker, then runs the supervisor relay without a SPIFFE socket. The broker reads the Gateway's public signing keys and checks the assertion. The relay's workload and origin fixtures use in-memory streams. The test checks the returned bearer header and verifies that rejected requests do not reach the origin. Production broker interoperability and sandbox isolation in an installed cluster require a separate rehearsal.
