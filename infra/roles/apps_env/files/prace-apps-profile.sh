# Managed by Ansible (roles/apps_env; the pods get it from roles/slinky's ConfigMap prace-apps-profile).
# The shared modulefiles in /apps (T88). Does nothing where /apps is absent or deferred, or where
# Lmod has not defined `module` (sourced after Lmod's own script: modules.sh in the images).
if [ -d /apps/modulefiles ] && type module >/dev/null 2>&1; then
  module use /apps/modulefiles
fi
# PRACE (owner, 6 Oct): the digital twin's name for the people who log in. Only in an interactive
# shell on the login pod (slurm-login-*); never in jobs, scp/sftp or remote commands, which must see
# no output. Once per session; the prompt names the cluster.
case $- in
  *i*)
    case $(uname -n) in
      slurm-login-*)
        if [ -z "${PRACE_BANNER_SHOWN:-}" ]; then
          PRACE_BANNER_SHOWN=1; export PRACE_BANNER_SHOWN
          printf '%s\n' "PRACE digital twin - login node" \
            "  Run work through Slurm with your project: sbatch -A <project> ...   (yours: sacctmgr -nP show assoc user=\$USER format=account)" \
            "  Software: module avail"
        fi
        PS1='[PRACE \u \W]\$ '
        ;;
    esac
    ;;
esac
