#!/bin/bash
# Stand-in test of the job environment (T88) where the Slinky images cannot be pulled (ghcr.io was
# refused on 1 Oct) and the slurm bench therefore cannot run. NOT the bench and NOT the fleet:
#  - the "worker" is Rocky 9 with the image's userland versions from Rocky's own repositories
#    (OpenMPI 4.1.1, PMIx 3.2.3, UCX 1.19, GCC 11.5 C/Fortran, Python 3.9), no Slurm, no GPUs;
#  - Lmod is replaced by fake-module.sh + lmod-api.lua (EPEL was not reachable either);
#  - the two-node MPI run uses mpirun over ssh between two containers on a 10.42.0.0/16 network
#    with the examples' TCP settings (mpi.sh's mpirun starts its daemons through Slurm instead).
# What it does test for real: DIR/apps as roles/apps_env made it (bench.py apps), mounted read-only;
# the profile snippet after a `module` definition; the runner's per-worker script and verdicts
# (slurm-policy-acceptance.py --env) as a non-root user; the relocated g++ and mpicxx; TCP between
# two hosts on the pod network's range.
#   infra/tests/apps_env/standin.sh DIR      (DIR as for bench.py apps; needs docker)
set -euo pipefail
INFRA=$(cd "$(dirname "$0")/../.." && pwd)
D=${1:?usage: standin.sh DIR}
[ -d "$D/apps/modulefiles" ] || { echo "refusing: $D/apps is not filled (bench.py apps --rpms ...)"; exit 2; }
IMG=${PRACE_STANDIN_IMAGE:-prace-apps-standin}
NET=prace-apps-standin
SUBNET=$(python3 -c "import yaml; print(yaml.safe_load(open('$INFRA/roles/k3s/defaults/main.yml'))['k3s_cluster_cidr'])")
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  docker build -q -t "$IMG" - <<'EOF'
FROM docker.io/rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
RUN dnf -y -q install openmpi openmpi-devel gcc gcc-gfortran python3 lua openssh-server openssh-clients hostname procps-ng findutils \
 && dnf clean all
EOF
fi
cleanup() { docker rm -f standin-a standin-b >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create --subnet "$SUBNET" "$NET" >/dev/null
for n in a b; do
  docker run -d --name "standin-$n" --hostname "standin-$n" --network "$NET" \
    -v "$D/apps:/apps:ro" \
    -v "$INFRA/roles/apps_env/files/prace-apps-profile.sh:/etc/profile.d/z01-prace-apps.sh:ro" \
    -v "$INFRA/tests/apps_env/fake-module.sh:/etc/profile.d/modules.sh:ro" \
    -v "$INFRA/tests/apps_env/lmod-api.lua:/usr/local/share/prace-test/lmod-api.lua:ro" \
    "$IMG" sleep infinity >/dev/null
  docker exec "standin-$n" sh -c 'useradd -m -u 30001 syn-alice && ssh-keygen -A -q && /usr/sbin/sshd'
done
# syn-alice's key on both (a shared home on the fleet; copied here)
docker exec -u syn-alice standin-a sh -c 'ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519 && cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys'
docker exec -u syn-alice standin-a sh -c 'tar -C ~ -cf - .ssh' | docker exec -i -u syn-alice standin-b sh -c 'tar -C ~ -xf -'

fail=0
check() { if [ "$2" = True ]; then echo "PASS: $1"; else echo "FAIL: $1 ($3)"; fail=1; fi; }
# the runner's own per-worker script and verdicts
script=$(python3 -c "
import importlib.util, os, sys
os.environ.update(PRACE_POLICY_SSH='false', PRACE_LOGIN='login.prace-test.invalid'); sys.argv=['x']
s=importlib.util.spec_from_file_location('r', '$INFRA/tools/slurm-policy-acceptance.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(m.WORKER_SCRIPT)")
for n in a b; do
  out=$(docker exec -u syn-alice -w /tmp "standin-$n" bash -lc "$script" 2>&1) && rc=0 || rc=$?
  python3 - "$INFRA" "standin-$n" "$rc" "$out" <<'EOF' || fail=1
import importlib.util, os, sys
infra, node, rc, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
os.environ.update(PRACE_POLICY_SSH="false", PRACE_LOGIN="login.prace-test.invalid"); sys.argv = ["x"]
s = importlib.util.spec_from_file_location("r", infra + "/tools/slurm-policy-acceptance.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
bad = 0
for name, ok, detail in m.worker_verdicts(node, rc, out, False):
    print(f"{'PASS' if ok else 'FAIL'}: stand-in {name}" + ("" if ok else f" ({detail})"))
    bad += not ok
sys.exit(1 if bad else 0)
EOF
done
# two hosts, one rank each, the examples' TCP settings (mpirun over ssh: the stand-in has no Slurm)
out=$(docker exec -u syn-alice -w /home/syn-alice standin-a bash -lc "
module load gcc/11.5 openmpi/4.1 && mpicc -O2 -o mpi_hello /apps/examples/mpi_hello.c && scp -q -o StrictHostKeyChecking=no mpi_hello standin-b: &&
export OMPI_MCA_pml=ob1 OMPI_MCA_btl=self,tcp OMPI_MCA_btl_tcp_if_include=$SUBNET OMPI_MCA_oob_tcp_if_include=$SUBNET \
       OMPI_MCA_plm_rsh_args='-o StrictHostKeyChecking=no' &&
mpirun --prefix /usr/lib64/openmpi -n 2 --host standin-a,standin-b --map-by node -x PATH -x LD_LIBRARY_PATH ./mpi_hello" 2>&1) || true
echo "$out" | sed 's/^/  /'
check "stand-in: two hosts, one rank each, over TCP on $SUBNET (mpirun over ssh, not srun)" \
  "$(grep -qx 'mpi: size=2 hosts=2 messages=1' <<<"$out" && echo True)" "see output"
# the examples' MCA environment names no RDMA or UCX transport
check "examples force ob1/tcp on $SUBNET and select no UCX/RDMA transport" \
  "$(grep -q "OMPI_MCA_pml=ob1 OMPI_MCA_btl=self,tcp OMPI_MCA_btl_tcp_if_include=$SUBNET" "$D/apps/examples/mpi.sh" \
     && ! grep -Eiq 'pml=ucx|btl=.*(openib|uct)|osc=ucx' "$D/apps/examples/mpi.sh" && echo True)" "mpi.sh"
# this OpenMPI's PMI clients: no PMI-2, which is why mpi.sh uses mpirun rather than srun (reported, not judged)
echo "INFO: this OpenMPI's PMI clients: $(docker exec standin-a /usr/lib64/openmpi/bin/ompi_info | grep -oE 'MCA pmix: [a-z0-9]+' | sed 's/MCA pmix: //' | xargs)"
exit $fail
