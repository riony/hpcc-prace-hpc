# Dependencies and attribution

| Dependency | Role | Upstream source / terms |
| --- | --- | --- |
| Slinky Slurm Operator 1.2.2 | Kubernetes controller and charts | https://github.com/SlinkyProject/slurm-operator/tree/v1.2.2 (Apache-2.0; upstream NOTICE applies) |
| Slurm | CPU scheduler and daemons in upstream images | https://slurm.schedmd.com/disclaimer.html (upstream distribution licences apply) |
| kind / Kubernetes | Disposable local cluster | https://github.com/kubernetes-sigs/kind (Apache-2.0) |
| Helm | Chart installation and lint | https://github.com/helm/helm (Apache-2.0) |
| cert-manager 1.18.2 | Operator webhook TLS | https://github.com/cert-manager/cert-manager (Apache-2.0) |
| containerd NRI | Optional mount guard dependency | https://github.com/containerd/nri (Apache-2.0) |
| NeMo Agent Toolkit | Optional model/tool workflows | https://github.com/NVIDIA/NeMo-Agent-Toolkit (upstream licence applies) |
| Ansible | Provisioning | https://github.com/ansible/ansible (upstream GPL licence applies) |
| Gitleaks | Release checks | https://github.com/gitleaks/gitleaks (MIT) |

Upstream dependencies are downloaded by explicit setup commands, not copied
into this first-party source release. Chart archive SHA-256s are recorded in
`demo/charts.lock.json`; downloaded charts retain their original content.
The optional NRI helper is supplied as first-party Go source and a pinned build
recipe. Its generated binary is ignored. Follow the recipe and update its hash
before using the advanced fleet role; no opaque prebuilt helper is shipped.
