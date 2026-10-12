#!/usr/bin/env python3
"""Managed by Ansible (roles/slinky). usage: prace-slurm-accounts --check|--apply SPEC.json|-|env

Makes the Slurm accounting database match the policy in git (accounts.yml and the role's
defaults; SPEC is what tasks/slurm-accounts.yml renders): QoS, accounts, user associations and
each user's default account, and every association's allowed and default QoS (SPEC from a file, stdin, or with "env" from $PRACE_SLURM_ACCOUNTS_SPEC,
which the role uses because it feeds this program itself on stdin). Projects are the groups with a GID in project_gids; a project's
members use only their projects, and a user in no project has no association, so cannot run jobs
(owner decision 30 Sep 2026). Prints one line per change, "plan: ..." (--check, nothing changed)
or "done: ...".

Fails closed: a failed query exits 2 before any change. Refuses (exit 3, no change at all) while
a user or association it would remove still has jobs in the queue, and lists them: the operator
cancels them deliberately and runs it again (user decision, 29 Sep 2026). Also refuses to lower a
pay-per-use credit (including unlimited to a finite credit) while any job on that credit has
started, in any state but waiting (owner decision 2 Oct 2026: no running job is killed for credit).
The queue is read in every state; a malformed row, an unknown state, or a job whose user, uid, account
or QoS is unreadable exits 2 before any change.
The check and the write are separate commands, so a waiting job could start in between: change
credits inside an owned maintenance window, with admission closed. Never touches the root
account or user, never deletes a QoS (an unmanaged one is only reported), and keeps accounting
history (sacctmgr removes associations, not jobs). Python 3.9 (the login node's)."""
import json
import os
import shlex
import subprocess
import sys

K = os.environ.get("PRACE_KUBECTL", "/usr/local/bin/k3s kubectl")
CTL = shlex.split(K) + ["-n", "slurm", "exec", "slurm-controller-0", "-c", "slurmctld", "--"]
KEEP = "root"
# QoS settings this script owns: sacctmgr "set" name -> its "format" (display) name. A setting
# absent from the spec is unlimited (Priority 0, no flags).
QOS_FIELDS = {"Priority": "Priority", "MaxJobsPerUser": "MaxJobsPU", "MaxSubmitJobsPerUser": "MaxSubmitPU",
              "MaxTRESPerUser": "MaxTRESPU", "MaxTRESPerAccount": "MaxTRESPA", "MaxTRESPerJob": "MaxTRES",
              "MaxWall": "MaxWall", "GrpTRES": "GrpTRES", "GrpTRESMins": "GrpTRESMins", "UsageFactor": "UsageFactor",
              "Flags": "Flags"}
TRES_FIELDS = ("MaxTRESPerUser", "MaxTRESPerAccount", "MaxTRESPerJob", "GrpTRES", "GrpTRESMins")
ACCOUNT_FIELDS = ("Fairshare", "GrpTRES")
# squeue --states=all, by extended state name: a job that has started (or is starting) holds
# resources and would be killed by a lower credit; a waiting one only waits longer; a finished one
# is history. Any other state is unknown and stops the run.
JOBS_STARTED = {"RUNNING", "CONFIGURING", "COMPLETING", "SUSPENDED", "STOPPED", "RESIZING", "SIGNALING",
                "STAGE_OUT", "UPDATE_DB", "POWER_UP_NODE"}
JOBS_WAITING = {"PENDING", "REQUEUED", "REQUEUE_HOLD", "REQUEUE_FED", "SPECIAL_EXIT"}
JOBS_DONE = {"COMPLETED", "CANCELLED", "FAILED", "TIMEOUT", "NODE_FAIL", "PREEMPTED", "BOOT_FAIL", "DEADLINE",
             "OUT_OF_MEMORY", "REVOKED"}
USAGE = "usage: prace-slurm-accounts --check|--apply SPEC.json|-|env"


class Failed(Exception):
    pass


# --- the policy from the spec -------------------------------------------------------------------
def desired(spec):
    """(qos, accounts, users, known_uids) the database should hold."""
    lo, hi = spec["project_gids"]
    projects = [g["name"] for g in spec["groups"] if lo <= int(g["gid"]) <= hi]
    accounts = {p: {"kind": "project", **spec["account_settings"]["project"]} for p in projects}
    qos = dict(spec["qos"])
    payg = spec.get("payg")
    for p in projects if payg else []:     # pay per use: each project's credit balance is its own QoS
        credits = int(payg["credits"].get(p, payg["credits"]["default"]))
        qos[payg["qos_prefix"] + p] = dict(payg["qos"], GrpTRESMins=f"billing={credits * 60}")
    users, uids = {}, {}
    for u in spec["users"]:
        uids[u["name"]] = int(u["uid"])
        mine = [g for g in u.get("groups", []) if g in projects]
        if u.get("state", "present") == "absent" or not mine:
            continue          # revoked, or in no project: no association (removed if it has one)
        users[u["name"]] = {"accounts": mine, "default": mine[0]}
    return qos, accounts, users, uids


def grant(spec, account):
    """(allowed QoS set, default QoS) of a non-root association in `account`: the policy's, and
    with pay per use also the account's own credit QoS (the submit filter sets it for payg jobs)"""
    allowed = set(spec["assoc_qos"]["allowed"])
    if spec.get("payg"):
        allowed.add(spec["payg"]["qos_prefix"] + account)
    return allowed, spec["assoc_qos"]["default"]


# --- values as sacctmgr prints them ---------------------------------------------------------------
def tres(s):
    s = str(s or "").strip()
    out = {k.strip().lower(): v.strip() for k, v in (p.split("=", 1) for p in s.split(",") if "=" in p)}
    if "mem" in out:          # sacctmgr may print 90G as 92160M: compare memory in MiB
        v = out["mem"].upper()
        scale = {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}.get(v[-1:], None)
        if scale is not None and v[:-1].replace(".", "", 1).isdigit():
            out["mem"] = str(int(float(v[:-1]) * scale))
        elif v.isdigit():
            out["mem"] = v
    return out


def credit(s):
    """The billing credit (credit-minutes) of a GrpTRESMins value; None = unlimited."""
    v = tres(s).get("billing")
    return None if v in (None, "", "-1") else int(v)


def minutes(s):
    """Slurm time ([D-]HH:MM:SS, HH:MM:SS, MM:SS or minutes) in minutes; None = no limit."""
    s = str(s or "").strip()
    if s in ("", "UNLIMITED", "INFINITE", "-1"):
        return None
    days, _, rest = s.rpartition("-") if "-" in s else ("0", "", s)
    parts = [int(x) for x in rest.split(":")]
    if len(parts) == 1:
        h, m, sec = 0, parts[0], 0
    elif len(parts) == 2:
        h, m, sec = 0, parts[0], parts[1]
    else:
        h, m, sec = parts
    return int(days) * 1440 + h * 60 + m + (1 if sec else 0)


def number(s):
    s = str(s if s is not None else "").strip()
    return None if s in ("", "-1") else int(s)


def flags(s):
    return {f.strip().lower() for f in str(s or "").split(",") if f.strip() and f.strip() != "-1"}


def same(field, want, have):
    if field in TRES_FIELDS:
        return tres(want) == tres(have)
    if field == "MaxWall":
        return minutes(want) == minutes(have)
    if field == "Flags":
        return flags(want) == flags(have)
    if field == "UsageFactor":
        return float(want if want not in (None, "") else 1) == float(have if have not in (None, "") else 1)
    if field in ("Priority", "Fairshare"):
        return (number(want) or 0) == (number(have) or 0)
    return number(want) == number(have)


def setting(field, want, have=""):
    """sacctmgr 'set' argument turning `have` into `want` (unset = no limit)."""
    if field in TRES_FIELDS:
        w, h = tres(want), tres(have)
        parts = [f"{k}={v}" for k, v in sorted(w.items())] + [f"{k}=-1" for k in sorted(h) if k not in w]
        return f"{field}={','.join(parts) if parts else '-1'}"
    if want in (None, ""):
        return f"{field}={'0' if field == 'Priority' else '1' if field == 'UsageFactor' else '-1'}"
    return f"{field}={want}"


# --- sacctmgr and squeue --------------------------------------------------------------------------
def query(args):
    try:
        r = subprocess.run(CTL + args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failed(f"{args[0]} {' '.join(args[1:4])}: {e}")
    if r.returncode != 0:
        raise Failed(f"{args[0]} {' '.join(args[1:4])}: {(r.stderr or r.stdout).strip() or 'exit %d' % r.returncode}")
    return [line.split("|") for line in r.stdout.splitlines() if line.strip()]


def current(cluster):
    qfmt = ["Name"] + list(QOS_FIELDS.values())
    qos = {}
    for row in query(["sacctmgr", "-nP", "show", "qos", "format=" + ",".join(qfmt)]):
        qos[row[0]] = dict(zip(QOS_FIELDS, row[1:]))
    accounts, assocs, qos_of = {}, {}, {}
    for acct, user, part, parent, share, grp, allowed, dflt in query(
            ["sacctmgr", "-nP", "show", "assoc", "where", f"cluster={cluster}",
             "format=Account,User,Partition,ParentName,Share,GrpTRES,QOS,DefaultQOS"]):
        if not user:
            accounts[acct] = {"Parent": parent, "Fairshare": share, "GrpTRES": grp}
        else:
            assocs.setdefault(user, set()).add((acct, part))
        # the QoS an association may use and its default, as sacctmgr shows them (inherited or own)
        qos_of[(user, acct, part)] = ({q for q in allowed.split(",") if q}, dflt)
    defaults = {row[0]: row[1] for row in query(["sacctmgr", "-nP", "show", "user", "format=User,DefaultAccount"])}
    jobs = []
    # Every field the guards read must be readable (Session A re-review B-R5: a blank account slipped
    # past the association-removal guard, which compares it literally): job id and state on every
    # row; on a row that is not finished also the user (a name, or the uid when unresolved), a
    # numeric uid, the account and the QoS. Anything else stops the run before any change.
    for row in query(["squeue", "-h", "-a", "--states=all", "-o", "%i|%u|%U|%a|%T|%q"]):
        if len(row) != 6 or any(x != x.strip() or " " in x for x in row) or not row[0] or not row[4]:
            raise Failed(f"squeue: unexpected row {'|'.join(row)!r}")
        if row[4] in JOBS_DONE:
            continue
        if row[4] not in JOBS_STARTED | JOBS_WAITING:
            raise Failed(f"squeue: job {row[0]} is in an unknown state {row[4]!r}")
        if not (row[1] and row[2].isdigit() and row[3] and row[5]):
            raise Failed(f"squeue: job {row[0]} has an unreadable user, uid, account or QoS: {'|'.join(row)!r}")
        jobs.append(row)
    return qos, accounts, assocs, defaults, jobs, qos_of


# --- the plan -------------------------------------------------------------------------------------
def plan(spec, state):
    """(changes, refusals): changes = [(text, sacctmgr args)] in a safe order."""
    cluster = spec["cluster"]
    want_qos, want_accts, want_users, uids = desired(spec)
    qos, accounts, assocs, defaults, jobs, qos_of = state

    def qos_set(acct):
        allowed, dflt = grant(spec, acct)
        return [f"QOS={','.join(sorted(allowed))}", f"DefaultQOS={dflt}"]

    def qos_ok(user, acct, part=""):
        return qos_of.get((user, acct, part)) == grant(spec, acct)
    changes, refusals, removals = [], [], []

    def queued(user, account=None):
        return [j for j in jobs if (j[1] == user or j[2] == str(uids.get(user, "")))
                and (account is None or j[3] == account)]

    for name, conf in sorted(want_qos.items()):
        have = qos.get(name)
        if have is None:
            args = [setting(f, conf[f]) for f in QOS_FIELDS if conf.get(f) not in (None, "")]
            changes.append((f"add qos {name} ({' '.join(args)})", ["add", "qos", name] + args))
            continue
        diff = [setting(f, conf.get(f), have.get(f, "")) for f in QOS_FIELDS if not same(f, conf.get(f), have.get(f, ""))]
        # owner decision 2 Oct: running jobs are never killed because credit runs out. Slurm kills a
        # running job whose QoS goes over GrpTRESMins, so a credit is never lowered (unlimited to a
        # finite credit included) while a job on it has started; jobs that only wait do not block
        want, had = credit(conf.get("GrpTRESMins")), credit(have.get("GrpTRESMins", ""))
        if want is not None and (had is None or want < had):
            started = [j for j in jobs if j[5] == name and j[4] not in JOBS_WAITING]
            if started:
                refusals.append(f"qos {name}: credit lowered from {'unlimited' if had is None else had} to {want} credit-minutes "
                                f"while jobs run on it (never kill a running job for credit): "
                                f"{', '.join(f'{j[0]} ({j[4]})' for j in started)}")
                continue
        if diff:
            changes.append((f"qos {name}: {' '.join(diff)}", ["modify", "qos", "where", f"name={name}", "set"] + diff))
    for name in sorted(set(qos) - set(want_qos)):
        print(f"note: qos {name} is not in the policy; left as it is")

    for name, conf in sorted(want_accts.items()):
        have = accounts.get(name)
        sets = [f"{f}={conf[f]}" for f in ACCOUNT_FIELDS if conf.get(f) not in (None, "")]
        if have is None:
            changes.append((f"add account {name} ({conf['kind']}; {' '.join(sets) or 'defaults'})",
                            ["add", "account", name, f"Cluster={cluster}", "Parent=root",
                             f"Description={conf['kind']} {name}", f"Organization={conf['kind']}"] + sets + qos_set(name)))
            continue
        diff = [setting(f, conf.get(f), have.get(f, "")) for f in ACCOUNT_FIELDS if not same(f, conf.get(f), have.get(f, ""))]
        if have.get("Parent") not in ("root", ""):
            diff.append("Parent=root")
        if not qos_ok("", name):
            diff += qos_set(name)
        if diff:
            changes.append((f"account {name}: {' '.join(diff)}",
                            ["modify", "account", "where", f"name={name}", f"cluster={cluster}", "set"] + diff))

    for user, conf in sorted(want_users.items()):
        have = assocs.get(user, set())
        for acct in conf["accounts"]:
            if (acct, "") not in have:
                extra = [f"DefaultAccount={conf['default']}"] if not have and acct == conf["default"] else []
                changes.append((f"add {user} to {acct}", ["add", "user", user, f"Account={acct}", f"Cluster={cluster}"] + extra))
        if defaults.get(user) != conf["default"] and have:
            changes.append((f"{user}: default account {defaults.get(user) or 'none'} -> {conf['default']}",
                            ["modify", "user", "where", f"name={user}", f"cluster={cluster}", "set", f"DefaultAccount={conf['default']}"]))
        # a QoS granted to (or made default for) the user alone, e.g. an unlimited one, would bypass
        # the normal limits: every kept association gets exactly the policy's QoS
        for acct in conf["accounts"]:
            if (acct, "") in have and not qos_ok(user, acct):
                was = qos_of.get((user, acct, ""), (set(), ""))
                allowed, dflt = grant(spec, acct)
                changes.append((f"{user} in {acct}: QoS {','.join(sorted(was[0])) or 'none'} (default {was[1] or 'none'}) -> "
                                f"{','.join(sorted(allowed))} (default {dflt})",
                                ["modify", "user", "where", f"name={user}", f"account={acct}", f"cluster={cluster}", "set"] + qos_set(acct)))
        for acct, part in sorted(have - {(a, "") for a in conf["accounts"]}):
            removals.append((user, acct, part))

    for user, acct, part in removals:
        busy = queued(user, acct)
        where = f"{user} from {acct}" + (f" (partition {part})" if part else "")
        if busy:
            refusals.append(f"{where}: jobs {', '.join(f'{j[0]} ({j[4]})' for j in busy)}")
            continue
        args = ["delete", "user", "where", f"name={user}", f"account={acct}", f"cluster={cluster}"]
        if part:
            args.append(f"partition={part}")
        changes.append((f"remove {where}", args))

    # users with no project in git (revoked, in no project, or never declared) lose every association at once
    for user in sorted(set(assocs) - set(want_users) - {KEEP}):
        busy = queued(user)
        if busy:
            refusals.append(f"user {user}: jobs {', '.join(f'{j[0]} ({j[4]})' for j in busy)}")
        else:
            accts = ",".join(sorted({a for a, _ in assocs[user]}))
            changes.append((f"remove user {user} (accounts {accts})", ["delete", "user", "where", f"name={user}", f"cluster={cluster}"]))

    for name in sorted(set(accounts) - set(want_accts) - {KEEP}):
        busy = [j for j in jobs if j[3] == name]
        if busy:
            refusals.append(f"account {name}: jobs {', '.join(f'{j[0]} ({j[4]})' for j in busy)}")
        else:
            changes.append((f"remove account {name}", ["delete", "account", "where", f"name={name}", f"cluster={cluster}"]))
    return changes, refusals


def main(argv):
    if len(argv) != 3 or argv[1] not in ("--check", "--apply"):
        print(USAGE, file=sys.stderr)
        return 2
    try:
        if argv[2] == "env":
            spec = json.loads(os.environ["PRACE_SLURM_ACCOUNTS_SPEC"])
        else:
            spec = json.load(sys.stdin if argv[2] == "-" else open(argv[2]))
        changes, refusals = plan(spec, current(spec["cluster"]))
    except (Failed, OSError, ValueError, KeyError) as e:
        print(f"no change: {e}", file=sys.stderr)
        return 2
    if refusals:
        for r in refusals:
            print(f"refused: {r}")
        print("no change: cancel these jobs deliberately (scancel <jobid>), then run again", file=sys.stderr)
        return 3
    verb = "plan" if argv[1] == "--check" else "done"
    for text, args in changes:
        if verb == "done":
            try:
                query(["sacctmgr", "-i"] + args)
            except Failed as e:
                print(f"failed: {text}: {e}", file=sys.stderr)
                return 1
        print(f"{verb}: {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
