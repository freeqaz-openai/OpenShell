# Register remote supervisor middleware

Set `supervisor.middleware` in the Gateway chart values. An empty list (the
default) adds no registration or volume. This example uses a private CA:

```yaml
supervisor:
  middleware:
    - name: protected-http
      grpcEndpoint: https://exchange.example.net:9444
      audience: protected-http
      maxPayloadBytes: 4194304
      timeout: 30s
      tlsCaConfigMapName: exchange-ca
      tlsCaKey: ca.crt
```

Create that ConfigMap in the Gateway namespace first. It contains the public CA
certificate, never a private key. The Gateway reads the certificate from a
read-only mount and distributes it with the registration. Omit
`tlsCaConfigMapName` to use the normal trust roots. The service must be reachable
when the Gateway negotiates the registry. Registration alone grants no traffic.
