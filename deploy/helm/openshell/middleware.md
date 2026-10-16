# Configure remote supervisor middleware

Set `supervisor.middleware` in the Gateway chart's values to register an existing
HTTPS middleware service. The list defaults to empty. The Gateway contacts each
service during startup to negotiate its capabilities; make the service available
before waiting for Gateway readiness. An unavailable or incompatible service
must not be replaced with an empty capability response.

```yaml
supervisor:
  middleware:
    - name: credential-authority
      grpcEndpoint: https://authority.platform.svc.cluster.local:9444
      audience: credential-access
      maxPayloadBytes: 4194304
      timeout: 30s
      tlsCaConfigMapName: authority-ca
      tlsCaKey: ca.crt
```

Create the public-root ConfigMap in the Gateway release namespace before starting
the Gateway. The chart mounts its selected key read-only and writes the path to
`tls_ca_cert_path` in `[[openshell.supervisor.middleware]]`. The Gateway reads
that public certificate and distributes the trust input to supervisors. This
mount must contain public CA certificates only, never a server or client private
key. The endpoint certificate must authenticate its exact DNS name or IP address.
Without `tlsCaConfigMapName`, the middleware transport uses its normal roots.

Each entry requires a unique identifier `name`, an HTTPS origin `grpcEndpoint`,
an `audience`, and a positive safe integer `maxPayloadBytes`. Optional `timeout`
accepts whole milliseconds or seconds from 10 ms to 30 s. `tlsCaKey` defaults to
`ca.crt` and requires a ConfigMap name. Unknown fields and insecure transport
refuse during chart rendering. Both StatefulSet and Deployment workloads use the
same registry and public-root mounts. This configuration does not select a
middleware implementation, grant credentials, or establish installed enforcement.

## Gateway administration and supervisor identity

Native Gateway PKI remains separate from middleware server trust. With TLS and
mTLS enabled, a verified client certificate supplies its CN as the User subject
and OU values as roles. Without an OIDC administrator role, an authenticated User
has platform administrator authority. Use a dedicated administrative client CA;
keep its private material and client keys in trusted control-plane clients.
Do not deliver them to Sandbox workloads. Existing OIDC administrator-role
checks continue to apply when configured.

The Gateway accepts a TLS connection without a client certificate so supervisor
bearer authentication can still run. That handshake behavior does not authenticate
an anonymous caller as an administrator. Supervisor extension JWT identity and
audience checks remain independent of the controller's mTLS certificate.

## Verify chart configuration

With installed Helm, Python 3.11+ and `yq` v4, run from the repository root:

```sh
HELM=/absolute/bin/helm python3 deploy/helm/test-middleware.py
```

This renders both workload kinds, parses the generated TOML, checks public-root
mounts and OIDC preservation, and checks invalid configurations refuse. It does
not start the Gateway, negotiate a live service, verify certificate role mapping,
or prove supervisor enforcement. If startup cannot negotiate the registry,
check service readiness, network reachability, endpoint SANs, CA contents,
audience and supported capabilities before changing the configuration.
