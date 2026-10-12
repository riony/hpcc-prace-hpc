#!/usr/bin/env python3
"""Drive a real interactive login on the PRACE login pod as a researcher would: type each command at a
human pace into the session, wait for the shell prompt, then the next. The whole session is recorded by
script(1) with timing (output and input), so it can be replayed first person and its commands extracted.

  pov-drive.py <user> <name> <commands.txt> [--ids-from <earlier name>]       (run in a private directory)

Keys: ~/.config/prace-lab/synthetic-keys/<user>_ed25519. The login pod's pinned host key: $PRACE_PRACE_KNOWN_HOSTS
(default ~/.config/prace-lab/prace-login.known_hosts). Files: <name>.tm, <name>.out, <name>.in (private: the
.out/.in headers carry the full ssh command); tools/session-export.py turns them into dashboard evidence.

commands.txt: one command per line ('#' lines are pauses for narration, not typed). With --ids-from, job
IDs that the earlier session's sbatch printed are mapped, in order, to this session's new IDs (a replay)."""
import os, pty, random, re, select, shlex, sys, time, signal
from pathlib import Path
os.umask(0o077)

HERE = os.getcwd()                              # recordings are written to the current directory
KNOWN = os.environ.get("PRACE_PRACE_KNOWN_HOSTS", os.path.expanduser("~/.config/prace-lab/prace-login.known_hosts"))
user, name, cmdfile = sys.argv[1:4]
ids_from = sys.argv[sys.argv.index("--ids-from") + 1] if "--ids-from" in sys.argv else None
if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
    sys.exit("REFUSED: invalid user or recording basename")
if any(Path(f"{name}.{ext}").exists() for ext in ("tm", "in", "out")):
    sys.exit("REFUSED: recording already exists")
key = os.path.expanduser(f"~/.config/prace-lab/synthetic-keys/{user}_ed25519")
ssh = ["ssh", "-tt", "-o", "BatchMode=yes", "-o", f"UserKnownHostsFile={KNOWN}",
       "-o", "StrictHostKeyChecking=yes", "-o", "IgnoreUnknown=WarnWeakCrypto", "-o", "WarnWeakCrypto=no-pq-kex",
       "-i", key, "-p", "32222", f"{user}@prace-login.example-tailnet.ts.net"]
argv = ["script", "-q", "-e", "--log-timing", f"{HERE}/{name}.tm", "--log-out", f"{HERE}/{name}.out",
        "--log-in", f"{HERE}/{name}.in", "-c", " ".join(shlex.quote(a) for a in ssh)]
PROMPT = re.compile(rb"\$ $")
SUBMIT = re.compile(rb"Submitted batch job (\d+)")
rng = random.Random(7)                          # a steady, human-looking rhythm (reproducible)

old_ids = []
if ids_from:
    old_ids = [m.decode() for m in SUBMIT.findall(open(f"{HERE}/{ids_from}.out", "rb").read())]
    if not old_ids or len(set(old_ids)) != len(old_ids):
        sys.exit("REFUSED: original recording lacks distinct submitted jobs")
new_ids = []

commands = Path(cmdfile).read_text().splitlines()
active = [line for line in commands if line.strip() and not line.startswith('#')]
if not active or active[-1].strip() != 'exit':
    sys.exit('REFUSED: command list must finish with exit')
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execvp(argv[0], argv)

import atexit

def cleanup_child():
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
    except (ProcessLookupError, ChildProcessError):
        pass

atexit.register(cleanup_child)
import fcntl, struct, termios
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))   # a 120x32 terminal, as recorded
os.set_blocking(fd, False)
buf = b""
def pump(timeout):
    """read whatever arrives within timeout; True if the session ended"""
    global buf
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return False
    try:
        data = os.read(fd, 65536)
    except OSError:
        return True
    if not data:
        return True
    buf += data
    sys.stdout.buffer.write(data); sys.stdout.flush()
    return False

def wait_prompt(limit=600):
    end = time.time() + limit
    while time.time() < end:
        if pump(0.2):
            raise SystemExit("STOP: session ended before the next prompt")
        if PROMPT.search(buf[-200:]):
            return True
    raise SystemExit(f"\nSTOP: no prompt within {limit} s")

def type_line(text):
    for ch in text:
        os.write(fd, ch.encode())
        time.sleep(rng.uniform(0.05, 0.14) if ch != " " else rng.uniform(0.08, 0.22))
        pump(0)
    time.sleep(rng.uniform(0.3, 0.6))
    os.write(fd, b"\r")

wait_prompt(60)                                 # the login banner and the first prompt
for line in commands:
    line = line.rstrip("\n")
    if not line.strip():
        continue
    if line.startswith("#"):                    # a pause, as a person reads the screen
        time.sleep(float(line[1:].strip() or 2))
        continue
    mapping = dict(zip(old_ids, new_ids))
    if old_ids:
        def replace_id(match):
            if match[0] not in mapping:
                raise SystemExit("STOP: replay references a job before its submission")
            return mapping[match[0]]
        line = re.sub(r"\b(?:" + "|".join(map(re.escape, old_ids)) + r")\b", replace_id, line)
    for i, new in enumerate(new_ids, 1):        # {1}, {2}: this session's own job IDs, in submission order
        line = line.replace("{%d}" % i, new)
    if re.search(r"\{[0-9]+\}", line):
        raise SystemExit("STOP: unresolved submitted-job placeholder")
    time.sleep(rng.uniform(0.6, 1.4))
    buf = b""
    type_line(line)
    if line.strip() == "exit":
        deadline = time.monotonic() + 15
        while not pump(1):
            if time.monotonic() >= deadline:
                raise SystemExit("STOP: session did not exit")
        break
    wait_prompt()
    new_ids += [m.decode() for m in SUBMIT.findall(buf)]
_, status = os.waitpid(pid, 0)
atexit.unregister(cleanup_child)
os.close(fd)
rc = os.waitstatus_to_exitcode(status)
if rc:
    raise SystemExit(f"STOP: recorded SSH session exited {rc}")
print(f"\n[{name}] done; job IDs {new_ids}" + (f" (replaying {old_ids})" if ids_from else ""), file=sys.stderr)
