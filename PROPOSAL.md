# Gateway-signed assertions for provider token grants

## Decision

Let a provider select `assertion_source: openshell_gateway` with the standard OAuth `grant_type: client_credentials`. The gateway mints a short-lived JWT on demand. An omitted assertion source continues to select SPIFFE, and `token_exchange` remains SPIFFE-only. Only the supervisor contacts the token endpoint and injects the resulting access token on admitted traffic. A grant-only profile can do this without an environment placeholder.

## Implementation

1. The operator registers the immutable provider ID, credential key and exact HTTPS token endpoint. The profile selects the assertion source. A profile alone cannot establish trust in a new recipient.
2. The gateway delivers the provider ID as credential metadata in the supervisor's installed snapshot. On a cache miss, the supervisor sends that ID and the selected credential through its authenticated gateway session. The gateway verifies that the provider currently attached under the name still has that ID, checks the current profile and operator registration, and mints an assertion addressed to the endpoint. It acknowledges the bound ID in the response, and the supervisor checks it before contacting the broker. A same-name replacement fails even if the replacement has its own registration. The workload cannot select the identity.
3. The broker verifies the signature, issuer, exact audience, expiry and sandbox/provider/credential binding, rejects replay, and authorizes the resource and scopes before issuing an access token. The supervisor uses its existing OAuth client, per-sandbox cache and header injection path. Each gateway replica bounds assertion requests separately from extension credentials at 60 per sandbox per minute, before catalog lookup. Withdrawing the registration stops new assertions but does not revoke cached or previously issued access tokens.

## Compatibility and rollout

The authored profile separates OAuth grant type from assertion source. The protobuf representation retains the combined numeric discriminator `3` for gateway-signed client credentials. This prevents older supervisors from treating an unknown, ignorable field as permission to use SPIFFE. Supporting clients send `openshell-profile-openshell-gateway-assertion-source: 1` on profile reads and writes, and check `LintProviderProfilesResponse.supports_openshell_gateway_assertion_source` before enabling the source. Supporting gateways refuse incompatible profile readers and writers and reject a stale update that strips the source from an existing credential. The mint response acknowledgment prevents a new supervisor from using an assertion returned by an older gateway that ignored the expected provider ID. To deliberately switch sources, remove the credential before adding the replacement.

Upgrade every gateway replica, supervisor and profile tool before opting in; register the provider on every gateway replica. An old unmodified component can still erase the selection if it processes authored YAML or normalizes a protobuf profile outside the negotiated API. A newly imported file whose source was already stripped is indistinguishable from a deliberately authored SPIFFE profile. Keep such components out of the path. Remove opted-in credentials and registrations before rollback.

## Local acceptance before EKS

- Run existing SPIFFE and token-exchange regression cases.
- Exercise the new normal supervisor path without a SPIFFE socket, using synthetic identities, a test Gateway and a local HTTPS broker. Verify the broker receives a valid assertion, issues a test access token, and the token reaches the intended upstream request. Verify that neither the assertion nor the issued token reaches the workload. If the fixture supplies a placeholder, verify its replacement on the upstream request. Record which boundaries the test actually exercises.
- Verify an unbound provider, wrong sandbox, unregistered recipient, wrong audience and expired assertion are refused at the owning boundary. Distinguish rejection before a request reaches the broker from rejection by the broker.
- Check generated API bindings, formatting, compilation and independent review. Record any untested integration or known limitations alongside the patch.

## Delivery

Publish a proposal branch on the existing fork for upstream discussion. Keep installed-environment promotion separate. Before enabling this mode, qualify the intended broker with the built gateway and supervisor on a disposable local installation and verify the intended workload behavior.

## Reproduce the wire check locally

From the repository root, run:

```sh
cargo test --locked -p openshell-supervisor-network --lib provider_client_assertion_wire
```

The test starts a loopback TLS Gateway and OAuth broker, then runs the supervisor relay without a SPIFFE socket. The broker reads the Gateway's public signing keys and checks the assertion. The relay's workload and origin fixtures use in-memory streams. The test checks the returned bearer header and verifies that rejected requests do not reach the origin. Production broker interoperability and sandbox isolation in an installed cluster require a separate rehearsal.
