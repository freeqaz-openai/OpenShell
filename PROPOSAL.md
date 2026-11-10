# Gateway-signed assertions for provider token grants

## Decision

Let a provider opt into OAuth client credentials using a short-lived JWT minted by the OpenShell Gateway. Keep SPIFFE as the default and preserve the existing token-exchange flow. The workload uses its existing opaque placeholder. Only the supervisor contacts the token endpoint.

## Implementation

1. The operator registers the permitted provider, credential key and exact HTTPS token endpoint. A provider profile selects the new grant mode. A profile alone cannot establish trust in a new recipient.
2. The supervisor requests an assertion through its authenticated Gateway session. The Gateway resolves the attached provider and current profile, checks the registration and mints a dedicated assertion addressed to that endpoint. The broker verifies the signature, issuer, audience, expiry and sandbox/provider binding.
3. The supervisor uses the existing OAuth client and header injection path. An unsupported mode or refused mint fails the request. Keep the new mode disabled during mixed-version upgrades until participating readers support it.

## Local acceptance before EKS

- Run existing SPIFFE and token-exchange regression cases.
- Exercise the new normal supervisor path without a SPIFFE socket, using synthetic identities, a test Gateway and a local HTTPS broker. Verify the broker receives a valid assertion, issues a test access token, and the token reaches the intended upstream request. Ensure the workload sees only its placeholder. Record which boundaries the test actually exercises.
- Verify an unbound provider, wrong sandbox, unregistered recipient, wrong audience and expired assertion are refused at the owning boundary. Distinguish rejection before a request reaches the broker from rejection by the broker.
- Check generated API bindings, formatting, compilation and independent review. Record any untested integration or known limitations alongside the patch.

## Delivery

Publish a proposal branch on the existing fork for upstream discussion. Keep EKS promotion separate. Before enabling this mode there, qualify the intended broker with the built Gateway and supervisor on a disposable local installation and verify model and Git behavior through the same Agent.
