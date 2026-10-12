#!/bin/bash
# Offline check of roles/apptainer's real files in the pinned slurmd image (the pods' job
# environment), on a workstation with docker. NOT the fleet and NOT CI (it needs the image, the
# pinned RPMs and an OCI archive of the pinned alpine). The container has no network.
#   infra/tests/apptainer/image-check.sh RPMS ARCHIVE OUT
#     RPMS     a directory with roles/apptainer's apptainer_rpms (checked by the unpack helper)
#     ARCHIVE  an OCI archive of the pinned alpine shaped like `ctr images export`'s
#     OUT      an empty directory for the results (results.txt) and the tree
# What it runs for real: roles/apps_env's unpack helper on the pinned RPMs; the role's site layer
# (its defaults' file list, its rendered apptainer.conf, both wrappers, the layout helper and the
# modulefile); the relocated
# Apptainer's own reading of every directive (apptainer config global --get); the libraries of every
# program in the tree; the module with the image's real Lmod, as a non-root user; the probe image
# built by files/prace-apptainer-probe.sh as root (built, then unchanged, then a changed image
# refused). What it cannot run here: a container as a non-root user. That needs unprivileged user
# namespaces, which this workstation's kernel restricts (Ubuntu: apparmor_restrict_unprivileged_userns),
# so it is recorded as INFO and left to the live acceptance (tools/apptainer-acceptance.py).
set -euo pipefail
INFRA=$(cd "$(dirname "$0")/../.." && pwd)
RPMS=$(cd "${1:?usage: image-check.sh RPMS ARCHIVE OUT}" && pwd)
ARCHIVE=$(cd "$(dirname "${2:?}")" && pwd)/$(basename "$2")
OUT=$(cd "${3:?}" && pwd)
[ -z "$(ls -A "$OUT")" ] || { echo "refusing: $OUT is not empty" >&2; exit 2; }
PLAYBOOK=$(command -v ansible-playbook || echo /home/operator/venvs/ansible-prace/bin/ansible-playbook)
IMAGE=$(python3 -c "import yaml; i=yaml.safe_load(open('$INFRA/roles/slinky/defaults/main.yml'))['slinky_images']['slurmd']; print(i['repository'] + '@' + i['digest'])")

# --- the role's templates and lists, rendered by the pinned Ansible with /apps as on the fleet
mkdir "$OUT/render"
cat > "$OUT/render/play.yml" <<EOF
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files: [$INFRA/roles/apptainer/defaults/main.yml]
  vars: {ansible_python_interpreter: auto_silent}
  tasks:
    - ansible.builtin.template: {src: $INFRA/roles/apptainer/templates/apptainer.conf.j2, dest: $OUT/render/apptainer.conf}
    - ansible.builtin.template: {src: $INFRA/roles/apptainer/templates/apptainer-wrapper.sh.j2, dest: $OUT/render/apptainer, mode: "0755"}
    - ansible.builtin.template: {src: $INFRA/roles/apptainer/templates/apptainer.lua.j2, dest: $OUT/render/module.lua}
    - ansible.builtin.template: {src: $INFRA/roles/apptainer/templates/apptainer-libexec-wrapper.sh.j2, dest: $OUT/render/libexec-wrapper, mode: "0755"}
    - ansible.builtin.copy:
        dest: $OUT/render/vars.sh
        content: |
          tree={{ apptainer_tree }}
          module={{ apptainer_module }}
          version={{ apptainer_version }}
          modulefiles={{ apptainer_modulefiles }}
          probe={{ apptainer_probe_image }}
          digest={{ apptainer_probe_digest }}
          conf_files="{{ apptainer_conf_files | join(' ') }}"
    - ansible.builtin.copy:
        dest: $OUT/render/manifest.sha256
        content: |
          {% for r in apptainer_rpms %}
          {{ r.sha256 }}  {{ r.file }}
          {% endfor %}
EOF
printf "[defaults]\n" > "$OUT/render/ansible.cfg"
ANSIBLE_CONFIG=$OUT/render/ansible.cfg ANSIBLE_LOCALHOST_WARNING=0 ANSIBLE_INVENTORY_UNPARSED_WARNING=0 \
  "$PLAYBOOK" -i localhost, "$OUT/render/play.yml" >"$OUT/render/ansible.log" 2>&1 \
  || { tail -30 "$OUT/render/ansible.log" >&2; exit 2; }

# PRACE_IMAGE_CHECK_PRIVILEGED=1: a privileged container, as the slurmd pods are (the workstation's
# kernel may still refuse a non-root user namespace; then the exec stays INFO)
timeout 900 docker run --rm --network none --memory 2g --cpus 2 ${PRACE_IMAGE_CHECK_PRIVILEGED:+--privileged} \
  -v "$RPMS:/rpms:ro" -v "$ARCHIVE:/archive.tar:ro" -v "$INFRA:/infra:ro" -v "$OUT:/out" \
  --entrypoint /bin/bash "$IMAGE" /infra/tests/apptainer/image-check-inner.sh
grep -c '^PASS' "$OUT/results.txt" | sed 's/$/ PASS/'
! grep '^FAIL' "$OUT/results.txt"
