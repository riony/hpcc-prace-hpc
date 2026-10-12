#!/usr/bin/env python3
"""Own one disposable kind cluster. Never use an ambient Kubernetes context."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NAME = "prace-public-demo"
NODE = NAME + "-control-plane"
IMAGE = "kindest/node:v1.34.0"


def run(*argv, capture=False, timeout=600):
    result = subprocess.run(list(argv), check=True, text=True,
                            stdout=subprocess.PIPE if capture else None, timeout=timeout)
    return result.stdout.strip() if capture else ""


def save(path, data):
    with path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


class Demo:
    def __init__(self, state):
        self.state = state
        self.kube = state / "kubeconfig"
        self.owner = state / "owner.json"

    def kubectl(self, *args, capture=False):
        return run("kubectl", "--kubeconfig", str(self.kube), "--context", "kind-" + NAME,
                   *args, capture=capture)

    def verify(self, api=True):
        if not self.owner.is_file():
            raise SystemExit("No ownership receipt; refusing this cluster.")
        receipt = json.loads(self.owner.read_text())
        actual = run("docker", "inspect", "--format", "{{.Id}}", NODE, capture=True)
        label = run("docker", "inspect", "--format", '{{index .Config.Labels "io.x-k8s.kind.cluster"}}', NODE, capture=True)
        if receipt["container_id"] != actual or label != NAME:
            raise SystemExit("Container ownership mismatch; preserve state for inspection.")
        if api:
            uid = self.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}", capture=True)
            if receipt["namespace_uid"] != uid:
                raise SystemExit("Cluster identity mismatch; preserve state for inspection.")

    def helm(self, *args):
        run("helm", "--kubeconfig", str(self.kube), "--kube-context", "kind-" + NAME, *args)

    def up(self):
        clusters = run("kind", "get", "clusters", capture=True).splitlines()
        if NAME in clusters or self.owner.exists() or self.kube.exists():
            raise SystemExit("Existing cluster/state refused; inspect it, then use down if owned.")
        # Download and check dependencies before creating any Kubernetes resources.
        run(sys.executable, str(ROOT / "tools/fetch-charts.py"), str(self.state / "charts"))
        run("kind", "create", "cluster", "--name", NAME, "--image", IMAGE,
            "--config", str(ROOT / "demo/kind.yaml"), "--kubeconfig", str(self.kube), "--wait", "180s")
        self.kube.chmod(0o600)
        receipt = {"container_id": run("docker", "inspect", "--format", "{{.Id}}", NODE, capture=True),
                   "namespace_uid": self.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}", capture=True)}
        save(self.owner, receipt)
        self.verify()
        charts = self.state / "charts"
        lock = json.loads((ROOT / "demo/charts.lock.json").read_text())
        self.helm("install", "cert-manager", str(charts / lock["cert-manager"]["file"]),
                  "--namespace", "cert-manager", "--create-namespace", "--set", "crds.enabled=true", "--wait", "--timeout", "300s")
        self.helm("install", "slurm-operator-crds", str(charts / lock["slurm-operator-crds"]["file"]), "--namespace", "slinky", "--create-namespace")
        self.helm("install", "slurm-operator", str(charts / lock["slurm-operator"]["file"]), "--namespace", "slinky", "--wait", "--timeout", "300s")
        self.kubectl("create", "namespace", "slurm")
        self.wait_for_admission(charts / lock["slurm"]["file"])
        self.helm("install", "slurm", str(charts / lock["slurm"]["file"]), "--namespace", "slurm", "--create-namespace", "-f", str(ROOT / "demo/values.example.yaml"))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            pods = json.loads(self.kubectl("get", "pods", "-n", "slurm", "-o", "json", capture=True))["items"]
            if len(pods) >= 3 and all(any(c.get("type") == "Ready" and c.get("status") == "True" for c in p.get("status", {}).get("conditions", [])) for p in pods):
                save(self.state / "ready.json", {"cluster": NAME, "ready": True})
                self.status()
                return
            time.sleep(5)
        raise SystemExit("Pod readiness deadline exceeded; owned state retained for diagnosis.")

    def wait_for_admission(self, chart):
        # Helm readiness may precede the webhook listener. Render in memory only:
        # template output contains fresh secrets and must never be logged.
        rendered = run("helm", "template", "slurm", str(chart), "--namespace", "slurm",
                       "-f", str(ROOT / "demo/values.example.yaml"), capture=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["kubectl", "--kubeconfig", str(self.kube), "--context", "kind-" + NAME,
                 "apply", "--dry-run=server", "-f", "-"], input=rendered, text=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
            if result.returncode == 0:
                return
            time.sleep(3)
        raise SystemExit("Admission dry-run deadline exceeded; state retained, no install retry.")

    def status(self):
        self.verify()
        self.kubectl("get", "pods", "-n", "slurm")

    def test(self):
        self.verify()
        pods = json.loads(self.kubectl("get", "pods", "-n", "slurm", "-o", "json", capture=True))["items"]
        candidates = [p["metadata"]["name"] for p in pods if any(c["name"] == "slurmctld" for c in p["spec"]["containers"])]
        if len(candidates) != 1:
            raise SystemExit("Expected exactly one Slurm controller.")
        pod = candidates[0]
        def execute(*args):
            return self.kubectl("exec", "-n", "slurm", pod, "-c", "slurmctld", "--", *args, capture=True)
        print(execute("sinfo"))
        # Actual job execution must return the expected content and exit code.
        output = execute("srun", "--partition=all", "--nodes=1", "--ntasks=1", "--time=00:01:00", "--immediate=60", "/bin/echo", "PRACE_CPU_JOB_OK")
        if output.strip() != "PRACE_CPU_JOB_OK":
            raise SystemExit("Slurm job output mismatch.")
        save(self.state / "result.json", {"scenario": "local-cpu-slurm", "job_completed": True,
                                         "output": output, "model_calls": 0})
        print("PASS: a real CPU job completed through Slurm.")

    def down(self):
        self.verify(api=False)
        run("kind", "delete", "cluster", "--name", NAME)
        if NAME in run("kind", "get", "clusters", capture=True).splitlines():
            raise SystemExit("Cluster still exists; ownership receipt retained.")
        # Move owned credentials and receipts to a private archive; never erase logs.
        archive = self.state / ("closed-" + str(time.time_ns()))
        archive.mkdir(mode=0o700)
        for name in ("kubeconfig", "owner.json", "ready.json", "result.json"):
            source = self.state / name
            if source.exists():
                source.rename(archive / name)
        print("Owned demo removed; private receipts retained outside the repository.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("up", "status", "test", "down"))
    parser.add_argument("--state", type=Path, default=Path.home() / ".local/state/hpcc-prace-hpc-public/demo")
    args = parser.parse_args()
    os.umask(0o077)
    state = args.state.expanduser().resolve()
    if state == ROOT or ROOT in state.parents:
        raise SystemExit("Runtime state must be outside the repository.")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_uid != os.getuid() or state.stat().st_mode & 0o077:
        raise SystemExit("State directory must be caller-owned and private (0700).")
    with (state / "operation.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        getattr(Demo(state), args.command)()

if __name__ == "__main__":
    main()
