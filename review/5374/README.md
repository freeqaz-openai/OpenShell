# Review: one-workspace gateway discovery permissions

**[Read the complete proposed diff](operator-discovery.patch)** · [Upstream issue #5374](https://github.com/NVIDIA/OpenShell/issues/5374)

The gateway needs to see which sandboxes exist, but should change workloads only in its own workspace. Operators can set up those permissions themselves today. This proposal lets Helm install and maintain the same narrow role with one optional value. Leaving it unset preserves current behavior.

The implementation is 29 lines in the ClusterRole template and three in values. Five tests check the complete list of grants and four invalid configurations. The rest is setup, troubleshooting and generated chart documentation. The retained Helm run passed 456/456 tests. No live cluster qualification is claimed.

This branch carries review material only. The patch is the exact Git diff against upstream base `af8182f7b63da6dd8bbea8b3c313227764ee0dea`, prepared at local commit `194320354ba5c6eaf9f3420b0a3fd7f70df686fc`. The older fork checkout is not the proposed upstream base. To inspect it in a checkout at that base, run `git apply --stat /path/to/operator-discovery.patch` or `git apply --check /path/to/operator-discovery.patch`. Patch SHA-256: `2ccb6e3fd128f7a280c14b31bd778a022f0b682c84b8584864dcc79a6a9b0b6e`.
