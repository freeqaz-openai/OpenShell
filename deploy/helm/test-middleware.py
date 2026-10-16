#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Render real Helm manifests and parse the middleware TOML; no cluster access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
HELM = os.environ.get("HELM", "helm")


def render(values):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as config:
        json.dump(values, config)
        config.flush()
        return subprocess.run(
            [HELM, "template", "openshell", str(ROOT / "deploy/helm/openshell"),
             "--namespace", "gateway", "--set", "agentSandbox.preflight.enabled=false",
             "-f", config.name], text=True, capture_output=True, check=False,
        )


def objects(result):
    assert result.returncode == 0, result.stderr
    parsed = subprocess.run(
        ["yq", "eval-all", "-o=json", "-I=0", ".", "-"], input=result.stdout,
        text=True, capture_output=True, check=True,
    )
    return [json.loads(line) for line in parsed.stdout.splitlines() if line != "null"]


def config(resources):
    resource = next(item for item in resources if item["kind"] == "ConfigMap" and "gateway.toml" in item.get("data", {}))
    return tomllib.loads(resource["data"]["gateway.toml"])["openshell"]


def main():
    defaults = config(objects(render({})))
    assert "supervisor" not in defaults, "default registry changed"
    entry = {"name": "credential-authority", "grpcEndpoint": "https://authority.platform.svc.cluster.local:9444",
             "audience": "credential-access", "tlsCaConfigMapName": "authority-ca", "tlsCaKey": "root.pem",
             "maxPayloadBytes": 4194304, "timeout": "30s"}
    for kind in ("statefulset", "deployment"):
        # Exercise both chart workload owners and preserve OIDC configuration beside middleware.
        values = {"workload": {"kind": kind}, "supervisor": {"middleware": [entry]},
                  "server": {"externalDbSecret": "database" if kind == "deployment" else "",
                             "hostGatewayIP": "172.30.42.1",
                             "oidc": {"issuer": "https://id.example.test", "audience": "gateway", "adminRole": "platform-admin"}}}
        resources = objects(render(values))
        actual = config(resources)
        assert actual["gateway"]["oidc"]["admin_role"] == "platform-admin"
        assert actual["drivers"]["kubernetes"]["host_gateway_ip"] == "172.30.42.1"
        assert actual["supervisor"]["middleware"] == [{
            "name": "credential-authority", "grpc_endpoint": entry["grpcEndpoint"],
            "audience": "credential-access", "tls_ca_cert_path": "/etc/openshell-middleware-ca/0/ca.crt",
            "max_payload_bytes": 4194304, "timeout": "30s", "allow_insecure_transport": False,
        }]
        workload = next(item for item in resources if item["kind"].lower() == kind)
        spec = workload["spec"]["template"]["spec"]
        volume = next(v for v in spec["volumes"] if v["name"] == "middleware-ca-0")
        assert volume["configMap"] == {"name": "authority-ca", "items": [{"key": "root.pem", "path": "ca.crt"}]}
        mount = next(v for v in spec["containers"][0]["volumeMounts"] if v["name"] == "middleware-ca-0")
        assert mount["readOnly"] and mount["mountPath"] == "/etc/openshell-middleware-ca/0"
    for change, expected in [
        ({"grpcEndpoint": "http://authority:9444"}, "HTTPS origin"),
        ({"grpcEndpoint": "https://" + ":".join(("user", "pass")) + "@authority:9444"}, "HTTPS origin"),
        ({"audience": ""}, "audience is required"),
        ({"maxPayloadBytes": 0}, "positive safe integer"),
        ({"maxPayloadBytes": -1}, "positive safe integer"),
        ({"maxPayloadBytes": 1.5}, "positive safe integer"),
        ({"timeout": "31s"}, "10ms to 30s"),
        ({"timeout": "9ms"}, "10ms to 30s"),
        ({"tlsCaConfigMapName": ""}, "tlsCaKey requires"),
        ({"allowInsecureTransport": True}, "unsupported supervisor.middleware field"),
    ]:
        result = render({"supervisor": {"middleware": [{**entry, **change}]}})
        assert result.returncode != 0 and expected in result.stderr, (change, result.stderr)
    duplicate = render({"supervisor": {"middleware": [entry, entry]}})
    assert duplicate.returncode != 0 and "unique identifiers" in duplicate.stderr
    print("PASS: default registry, two workload owners, parsed TLS registration, public CA mounts, OIDC preservation, 11 refusals")


if __name__ == "__main__":
    main()
