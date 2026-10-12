#!/usr/bin/env python3
"""Read-only inspector for playbooks/beegfs-disk-wipe.yml. It never writes to a disk, to LVM,
to the LVM devices file or to NVRAM: it only runs lsblk, udevadm info, pvs/vgs/lvs, dmsetup info,
swapon --show, wipefs --no-act, blkid -p, efibootmgr -v and lvmdevices (listing).

  plan:    nvme-wipe-inspect.py --disk SERIAL=EUI --disk SERIAL=EUI --os-wwn WWN \\
               --model MODEL --size BYTES --legacy-vg rl --legacy-lvs home,root,swap
  verify:  the same arguments plus --verify-after PLAN.json   (after the wipe)
  record:  nvme-wipe-inspect.py --record                        (evidence text, every NVMe)
  unfinished: nvme-wipe-inspect.py --unfinished DIR             (earlier runs that started
           changing this node and never verified: their records under DIR, as JSON)

The two data NVMes are resolved by serial AND EUI, never by their /dev/nvmeXn1 names (g005's
names swapped across a reboot). The pre-state must be exactly one of:
  blank  no partition, no signature (wipefs, blkid -p), no LVM trace: nothing to do;
  rl     the old OS layout of g003/g004 (node facts, 28 Sep): first NVMe p1 vfat (old ESP),
         p2 xfs (old /boot), p3 PV; second NVMe p1 PV; VG rl on exactly those two PVs with
         exactly the LVs home, root and swap; nothing mounted or in swap; every rl
         device-mapper device open count 0.
Anything else is refused: exit 1 with 'NVME WIPE REFUSED: ...' on stderr. The plan (JSON on
stdout) names every device to wipe and the UEFI entries to delete: only entries whose device
path is on the old NVMe ESP's PARTUUID, never BootCurrent, never the head of BootOrder; and
for the 'rl' layout BootCurrent and the head of BootOrder must both boot from a partition of
the OS disk (plan section 6 step 7: the RAID1 ESP entry stays first).
"""
import argparse
import json
import os
import re
import subprocess
import sys

NVME_PATH = re.compile(r"^/dev/nvme[0-9]+n[0-9]+$")
SERIAL = re.compile(r"^[A-Za-z0-9_-]{4,40}$")
EUI = re.compile(r"^eui\.[0-9a-f]{16}(?:[0-9a-f]{16})?$")
WWN = re.compile(r"^(?:[0-9a-f]{16}|[0-9a-f]{32})$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DEVICES_FILE = "/etc/lvm/devices/system.devices"


class Refused(Exception):
    pass


def require(ok, why):
    if not ok:
        raise Refused(why)


def run(*args, ok=(0,)):
    r = subprocess.run(args, capture_output=True, text=True, timeout=120, env=dict(os.environ, LC_ALL="C"))
    if ok is not None:
        require(r.returncode in ok, "read-only command failed: %s (rc %d): %s"
                % (" ".join(args), r.returncode, (r.stderr or r.stdout).strip()[:300]))
    return r


def jrun(*args):
    return json.loads(run(*args).stdout)


def clean(v):
    return (v or "").strip() if isinstance(v, str) or v is None else str(v).strip()


def walk(dev):
    yield dev
    for child in dev.get("children") or []:
        yield from walk(child)


def mounts(dev):
    m = dev.get("mountpoints")
    if m is None:
        m = [dev.get("mountpoint")]
    return [x for x in m if x]


def lvm(cmd, fields, devices=None, all_lvs=False):
    args = [cmd, "--reportformat", "json", "--units", "b", "--nosuffix", "-o", fields]
    if all_lvs:
        args.append("-a")
    if devices:
        args += ["--devices", ",".join(devices)]
    key = {"pvs": "pv", "vgs": "vg", "lvs": "lv"}[cmd]
    return [row for rep in jrun(*args).get("report", []) for row in rep.get(key, [])]


def parse_efi(text):
    current, order, entries = None, [], {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        m = re.match(r"^BootCurrent: ([0-9A-Fa-f]{4})\s*$", line)
        if m:
            current = m.group(1).upper()
            continue
        m = re.match(r"^BootOrder: ([0-9A-Fa-f,]*)\s*$", line)
        if m:
            order = [x.upper() for x in m.group(1).split(",") if x]
            continue
        m = re.match(r"^Boot([0-9A-Fa-f]{4})\*? ", line)
        if m:
            entries[m.group(1).upper()] = line
    return current, order, entries


def device_path(line):
    """The device path of an efibootmgr -v entry (after the tab), never its description."""
    return line.split("\t", 1)[1] if "\t" in line else ""


def efi_on_partuuid(entries, partuuid):
    rx = re.compile(r"HD\([0-9]+,GPT," + re.escape(partuuid) + r",", re.I)
    return sorted(i for i, line in entries.items() if rx.search(device_path(line)))


def parse_devices_file(r):
    """lvmdevices listing -> (enabled, entries). A disabled/absent devices file has no entries."""
    text = r.stdout + r.stderr
    if r.returncode != 0:
        require("Devices file not enabled" in text or "Devices file does not exist" in text,
                "lvmdevices failed (rc %d): %s" % (r.returncode, text.strip()[:300]))
        return False, []
    entries = []
    for line in r.stdout.splitlines():
        kv = dict(t.split("=", 1) for t in line.split() if "=" in t)
        if "IDNAME" in kv or "DEVNAME" in kv:
            entries.append(kv)
    return True, entries


# ---------------------------------------------------------------- collection (read-only)
def resolve(args):
    devs = jrun("lsblk", "-J", "-b", "-d", "-o", "NAME,KNAME,PATH,TYPE,SERIAL,MODEL,SIZE,WWN")["blockdevices"]
    disks = []
    for serial, eui in args.disk:
        by_serial = [d for d in devs if clean(d.get("serial")) == serial]
        by_eui = [d for d in devs if clean(d.get("wwn")).lower() == eui]
        require(len(by_serial) == 1, "serial %s: %d devices, need exactly one" % (serial, len(by_serial)))
        require(len(by_eui) == 1, "EUI %s: %d devices, need exactly one" % (eui, len(by_eui)))
        d = by_serial[0]
        require(d.get("path") == by_eui[0].get("path"), "serial %s and EUI %s are different devices (%s, %s)"
                % (serial, eui, d.get("path"), by_eui[0].get("path")))
        path = d.get("path") or ""
        require(d.get("type") == "disk" and NVME_PATH.match(path), "serial %s is not an NVMe namespace (%s %s)"
                % (serial, d.get("type"), path))
        require(clean(d.get("model")) == args.model, "%s (%s): model %r, expected %s"
                % (path, serial, clean(d.get("model")), args.model))
        require(int(d.get("size") or 0) == args.size, "%s (%s): size %s bytes, expected %d"
                % (path, serial, d.get("size"), args.size))
        links = run("udevadm", "info", "--query=symlink", "--name=" + path).stdout.split()
        require("disk/by-id/nvme-" + eui in links, "%s: udev has no disk/by-id/nvme-%s link" % (path, eui))
        disks.append({"serial": serial, "eui": eui, "path": path, "kname": d.get("kname") or d.get("name")})
    require(disks[0]["path"] != disks[1]["path"], "both serials resolved to %s" % disks[0]["path"])
    osd = [d for d in devs if clean(d.get("wwn")).lower() in ("0x" + args.os_wwn, args.os_wwn)]
    require(len(osd) == 1, "OS disk WWN %s: %d devices, need exactly one" % (args.os_wwn, len(osd)))
    require(osd[0]["path"] not in [d["path"] for d in disks], "a data NVMe resolved to the OS disk")
    return disks, osd[0]["path"]


def collect(args):
    disks, os_disk = resolve(args)
    paths = [d["path"] for d in disks]
    tree = jrun("lsblk", "-J", "-b", "-o", "NAME,KNAME,PATH,TYPE,FSTYPE,PARTUUID,PTTYPE,MOUNTPOINTS", *paths)
    trees = {d.get("path"): d for d in tree["blockdevices"]}
    require(sorted(trees) == sorted(paths), "lsblk returned %s for %s" % (sorted(trees), paths))
    nvme_paths = sorted({n["path"] for p in paths for n in walk(trees[p]) if n.get("type") in ("disk", "part")})
    os_tree = jrun("lsblk", "-J", "-b", "-o", "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,UUID,PARTUUID", os_disk)
    t = {
        "disks": disks, "os_disk": os_disk, "trees": trees, "nvme_paths": nvme_paths,
        "os_tree": os_tree["blockdevices"],
        "partuuids": [clean(d.get("partuuid")).lower() for d in
                      jrun("lsblk", "-J", "-l", "-o", "PATH,PARTUUID")["blockdevices"] if clean(d.get("partuuid"))],
        "nvme_pvs": lvm("pvs", "pv_name,pv_uuid,vg_name,vg_uuid", nvme_paths),
        "nvme_vgs": lvm("vgs", "vg_name,vg_uuid,pv_count,lv_count,snap_count,vg_missing_pv_count", nvme_paths),
        "nvme_lvs": lvm("lvs", "vg_name,vg_uuid,lv_name,lv_uuid", nvme_paths, all_lvs=True),
        "sys_pvs": lvm("pvs", "pv_name,pv_uuid,vg_name,vg_uuid,pv_size"),
        "sys_vgs": lvm("vgs", "vg_name,vg_uuid,vg_size,pv_count,lv_count"),
        "sys_lvs": lvm("lvs", "vg_name,vg_uuid,lv_name,lv_uuid,lv_size,lv_path", all_lvs=True),
        "wipefs": {p: run("wipefs", "--no-act", p).stdout.strip() for p in paths},
        "blkid": {p: run("blkid", "-p", p, ok=(0, 2)).stdout.strip() for p in paths},
        "swaps": run("swapon", "--show=NAME", "--noheadings", "--raw").stdout.split(),
    }
    t["dm"] = []
    for line in run("dmsetup", "info", "-c", "--noheadings", "--separator", "|", "-o", "name,uuid,open").stdout.splitlines():
        line = line.strip()
        if not line or line == "No devices found":
            continue
        fields = line.split("|")
        require(len(fields) == 3 and fields[2].strip().isdigit(), "unexpected dmsetup line: %r" % line)
        t["dm"].append({"name": fields[0].strip(), "uuid": fields[1].strip(), "open": int(fields[2])})
    t["devfile_enabled"], t["devfile"] = parse_devices_file(run("lvmdevices", ok=None))
    t["efi"] = dict(zip(("current", "order", "entries"), parse_efi(run("efibootmgr", "-v").stdout)))
    return t


def nvme_devfile_entries(t, pvids=()):
    idents = [d["serial"].lower() for d in t["disks"]] + [d["eui"][4:] for d in t["disks"]]
    out = []
    for e in t["devfile"]:
        idname = e.get("IDNAME", "").lower()
        if (e.get("DEVNAME") in t["nvme_paths"] or any(i in idname for i in idents)
                or e.get("PVID", "").replace("-", "") in pvids):
            out.append(e)
    return out


def os_partuuids(t):
    return sorted({clean(n.get("partuuid")).lower() for d in t["os_tree"] for n in walk(d)
                   if n.get("type") == "part" and UUID.match(clean(n.get("partuuid")).lower())})


def keep_snapshot(t, vg_uuid):
    """What must not change: the OS disk's structure (mounts excluded: pod bind mounts come and
    go) and every LVM row that is not the old VG or on the data NVMes."""
    def drop(rows):
        return sorted((r for r in rows if r.get("vg_uuid") != vg_uuid and r.get("pv_name") not in t["nvme_paths"]),
                      key=lambda r: json.dumps(r, sort_keys=True))
    return {"os_tree": t["os_tree"], "pvs": drop(t["sys_pvs"]), "vgs": drop(t["sys_vgs"]), "lvs": drop(t["sys_lvs"])}


# ---------------------------------------------------------------- classification
def blank_problems(t, pvids=()):
    p = []
    for d in t["disks"]:
        n = t["trees"][d["path"]]
        kids = [c.get("name") for c in n.get("children") or []]
        if kids:
            p.append("%s has partitions or holders %s" % (d["path"], kids))
        for col in ("fstype", "pttype"):
            if clean(n.get(col)):
                p.append("%s %s is %s" % (d["path"], col, clean(n.get(col))))
        if t["wipefs"][d["path"]]:
            p.append("%s: wipefs lists signatures" % d["path"])
        if t["blkid"][d["path"]]:
            p.append("%s: blkid -p finds %s" % (d["path"], t["blkid"][d["path"]]))
    if t["nvme_pvs"]:
        p.append("LVM sees PVs on the NVMes: %s" % sorted(r.get("pv_name") for r in t["nvme_pvs"]))
    stale = nvme_devfile_entries(t, pvids)
    if stale:
        p.append("the LVM devices file lists the NVMes: %s" % sorted(e.get("DEVNAME", "?") for e in stale))
    return p


def rl_layout(t, vg, lvs):
    """Problems with the known 'rl' layout, and the facts it yields when there are none."""
    d0, d1 = t["disks"]
    n0, n1 = t["trees"][d0["path"]], t["trees"][d1["path"]]
    parts0, parts1 = n0.get("children") or [], n1.get("children") or []
    want0 = [(d0["kname"] + "p1", "part", "vfat"), (d0["kname"] + "p2", "part", "xfs"),
             (d0["kname"] + "p3", "part", "LVM2_member")]
    want1 = [(d1["kname"] + "p1", "part", "LVM2_member")]
    got0 = sorted((c.get("name"), c.get("type"), clean(c.get("fstype"))) for c in parts0)
    got1 = sorted((c.get("name"), c.get("type"), clean(c.get("fstype"))) for c in parts1)
    p = []
    if got0 != want0:
        p.append("first NVMe %s partitions %s, expected %s" % (d0["path"], got0, want0))
    if got1 != want1:
        p.append("second NVMe %s partitions %s, expected %s" % (d1["path"], got1, want1))
    if p:
        return p, None
    byname = {c["name"]: c for c in parts0 + parts1}
    esp, boot = byname[d0["kname"] + "p1"], byname[d0["kname"] + "p2"]
    pv_parts = [byname[d0["kname"] + "p3"], byname[d1["kname"] + "p1"]]
    pv_paths = [c["path"] for c in pv_parts]
    dm_names = {vg + "-" + lv for lv in lvs}
    for c in (esp, boot):
        if c.get("children"):
            p.append("%s has holders %s" % (c["path"], [k.get("name") for k in c["children"]]))
    for c in pv_parts:
        for k in c.get("children") or []:
            if k.get("type") != "lvm" or k.get("name") not in dm_names or k.get("children"):
                p.append("%s holder %s (%s) is not an LV of %s" % (c["path"], k.get("name"), k.get("type"), vg))
    for d in (n0, n1):
        for n in walk(d):
            if mounts(n):
                p.append("%s is mounted at %s" % (n.get("path"), mounts(n)))
    nodes = [n for d in (n0, n1) for n in walk(d)]
    in_swap = set(t["swaps"]) & ({"/dev/" + clean(n.get("kname")) for n in nodes} | {n.get("path") for n in nodes})
    if in_swap:
        p.append("in swap: %s" % sorted(in_swap))

    pvs = {r.get("pv_name"): r for r in t["nvme_pvs"]}
    if sorted(pvs) != sorted(pv_paths) or any(r.get("vg_name") != vg for r in pvs.values()):
        p.append("PVs on the NVMes %s, expected exactly %s in VG %s"
                 % (sorted((k, r.get("vg_name")) for k, r in pvs.items()), pv_paths, vg))
        return p, None
    uuids = {r.get("vg_uuid") for r in pvs.values()}
    if len(uuids) != 1:
        return p + ["the two PVs belong to different VGs %s" % sorted(uuids)], None
    vg_uuid = uuids.pop()
    vgs = [(r.get("vg_name"), r.get("vg_uuid"), r.get("pv_count"), r.get("snap_count"),
            r.get("vg_missing_pv_count")) for r in t["nvme_vgs"]]
    if vgs != [(vg, vg_uuid, "2", "0", "0")]:
        p.append("VGs on the NVMes %s, expected only %s %s with 2 PVs, no snapshot, none missing"
                 % (vgs, vg, vg_uuid))
    names = sorted(r.get("lv_name") for r in t["nvme_lvs"])
    if names != sorted(lvs) or any(r.get("vg_uuid") != vg_uuid for r in t["nvme_lvs"]):
        p.append("LVs on the NVMes %s, expected exactly %s in %s"
                 % (sorted((r.get("vg_name"), r.get("lv_name")) for r in t["nvme_lvs"]), sorted(lvs), vg))
    others = sorted({r.get("vg_uuid") for r in t["sys_vgs"] if r.get("vg_name") == vg} - {vg_uuid})
    if others:
        p.append("another VG named %s exists: %s" % (vg, others))
    elsewhere = sorted(r.get("pv_name") for r in t["sys_pvs"] if r.get("vg_uuid") == vg_uuid
                       and r.get("pv_name") not in pv_paths)
    if elsewhere:
        p.append("VG %s also has PVs %s" % (vg, elsewhere))
    prefix = "LVM-" + vg_uuid.replace("-", "")
    rl_dm = [r for r in t["dm"] if r["uuid"].startswith(prefix)]
    for r in rl_dm:
        if r["open"] != 0 or r["name"] not in dm_names:
            p.append("device-mapper %s (open %d) is not an idle LV of %s" % (r["name"], r["open"], vg))

    esp_uuid = clean(esp.get("partuuid")).lower()
    if not UUID.match(esp_uuid):
        p.append("old ESP %s has no usable PARTUUID (%r)" % (esp["path"], esp_uuid))
    elif t["partuuids"].count(esp_uuid) != 1:
        p.append("PARTUUID %s of the old ESP is not unique on this node" % esp_uuid)
    pv_uuids = [pvs[x].get("pv_uuid") for x in pv_paths]
    devfile = nvme_devfile_entries(t, {u.replace("-", "") for u in pv_uuids})
    for e in devfile:
        if e.get("DEVNAME") not in t["nvme_paths"]:
            p.append("devices-file entry %s names %s, not a device of these NVMes" % (e.get("IDNAME"), e.get("DEVNAME")))
    efi = t["efi"]
    delete = []
    if not efi["current"] or not efi["order"]:
        p.append("no BootCurrent/BootOrder in efibootmgr -v (not booted by UEFI?)")
    elif UUID.match(esp_uuid):
        delete = efi_on_partuuid(efi["entries"], esp_uuid)
        if efi["current"] in delete:
            p.append("BootCurrent %s boots from the old NVMe ESP" % efi["current"])
        if efi["order"][0] in delete:
            p.append("the head of BootOrder (%s) boots from the old NVMe ESP" % efi["order"][0])
        on_os = {i for u in os_partuuids(t) for i in efi_on_partuuid(efi["entries"], u)}
        if efi["current"] not in on_os:
            p.append("BootCurrent %s does not boot from a partition of the OS disk %s" % (efi["current"], t["os_disk"]))
        if efi["order"][0] not in on_os:
            p.append("the head of BootOrder (%s) is not an entry on the OS disk %s" % (efi["order"][0], t["os_disk"]))
    if p:
        return p, None
    return [], {
        "vg": {"name": vg, "uuid": vg_uuid, "pvs": pv_paths, "pv_uuids": pv_uuids, "lvs": sorted(lvs)},
        "esp": {"path": esp["path"], "partuuid": esp_uuid},
        # wipe order: the first NVMe's partitions from the last to the first, then the second's
        "partitions": [byname[d0["kname"] + s]["path"] for s in ("p3", "p2", "p1")] + [pv_paths[1]],
        "devices_file": sorted(e["DEVNAME"] for e in devfile),
        "efi_delete": delete,
    }


def plan(args):
    t = collect(args)
    not_blank = blank_problems(t)
    out = {"host_disks": t["disks"], "os_disk": t["os_disk"], "lvm_devices": t["nvme_paths"],
           "whole_disks": [d["path"] for d in t["disks"]], "efi": t["efi"],
           "devices_file_enabled": t["devfile_enabled"]}
    if not not_blank:
        out.update(state="blank", keep=keep_snapshot(t, None), partitions=[], devices_file=[], efi_delete=[])
        return out
    not_rl, facts = rl_layout(t, args.legacy_vg, args.legacy_lvs)
    require(not not_rl, "neither blank nor the known '%s' layout. Not %s: %s. Not blank: %s"
            % (args.legacy_vg, args.legacy_vg, "; ".join(not_rl), "; ".join(not_blank)))
    out.update(state=args.legacy_vg, keep=keep_snapshot(t, facts["vg"]["uuid"]), **facts)
    return out


def verify(args, before):
    t = collect(args)
    require([d["path"] for d in t["disks"]] == before["whole_disks"],
            "the NVMes now resolve to %s, before %s" % ([d["path"] for d in t["disks"]], before["whole_disks"]))
    vg = before.get("vg") or {}
    p = blank_problems(t, {u.replace("-", "") for u in vg.get("pv_uuids", [])})
    name, uuid = vg.get("name", args.legacy_vg), vg.get("uuid")
    left = sorted({r.get("vg_name") for r in t["sys_vgs"] + t["nvme_vgs"] if r.get("vg_name") == name or r.get("vg_uuid") == uuid})
    if left:
        p.append("VG %s still present" % left)
    if uuid and any(r["uuid"].startswith("LVM-" + uuid.replace("-", "")) for r in t["dm"]):
        p.append("device-mapper still has LVs of %s" % name)
    if any(r["name"].startswith(name + "-") for r in t["dm"]):
        p.append("device-mapper still has %s-* devices" % name)
    keep = keep_snapshot(t, uuid)
    for k in ("os_tree", "pvs", "vgs", "lvs"):
        if keep[k] != before["keep"][k]:
            p.append("%s changed" % {"os_tree": "the OS disk (lsblk)"}.get(k, "LVM %s outside %s" % (k, name)))
    efi, old, gone = t["efi"], before["efi"], before["efi_delete"]
    if efi["current"] != old["current"]:
        p.append("BootCurrent %s, before %s" % (efi["current"], old["current"]))
    if not efi["order"] or efi["order"][0] != old["order"][0]:
        p.append("head of BootOrder %s, before %s" % (efi["order"][:1], old["order"][:1]))
    if efi["order"] != [x for x in old["order"] if x not in gone]:
        p.append("BootOrder %s, expected %s" % (efi["order"], [x for x in old["order"] if x not in gone]))
    for i in gone:
        if i in efi["entries"]:
            p.append("UEFI entry %s still present" % i)
    for i, line in old["entries"].items():
        if i not in gone and efi["entries"].get(i) != line:
            p.append("UEFI entry %s changed or missing" % i)
    for i in efi["entries"]:
        if i not in old["entries"]:
            p.append("new UEFI entry %s" % i)
    require(not p, "; ".join(p))
    return {"verified": True, "state": "blank", "whole_disks": before["whole_disks"],
            "efi_deleted": gone, "boot_current": efi["current"], "boot_order_head": efi["order"][0]}


# ---------------------------------------------------------------- earlier runs
def unfinished(root):
    """Run directories under ROOT whose wipe started (wipe-started.json) and never finished
    (no wipe-finished). 'originals' are those that are not themselves resumptions; each carries
    its own plan, which a resumption verifies against."""
    runs = []
    for d in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        path = os.path.join(root, d)
        if not os.path.isfile(os.path.join(path, "wipe-started.json")) or os.path.exists(os.path.join(path, "wipe-finished")):
            continue
        with open(os.path.join(path, "wipe-started.json")) as fh:
            started = json.load(fh)
        with open(os.path.join(path, "plan.json")) as fh:
            plan_ = json.load(fh)
        runs.append({"dir": path, "stamp": d, "started": started, "plan": plan_})
    return {"all": [r["dir"] for r in runs], "originals": [r for r in runs if not r["started"].get("resumes")]}


# ---------------------------------------------------------------- evidence text
def record():
    """Plain evidence of the node's storage and boot state: every command, its output, its rc."""
    out = []

    def show(*args):
        r = run(*args, ok=None)
        out.append("\n########## %s\n%s%s## rc=%d\n" % (" ".join(args), r.stdout, r.stderr, r.returncode))
        return r

    show("date", "-Is")
    show("lsblk", "-o", "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,UUID,PARTUUID,PARTTYPE,PTTYPE,PTUUID,MOUNTPOINTS,MODEL,SERIAL,WWN")
    r = show("lsblk", "-J", "-b", "-o", "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,UUID,PARTUUID,PARTTYPE,PTTYPE,PTUUID,MOUNTPOINTS,MODEL,SERIAL,WWN")
    try:
        nvme = sorted(n["path"] for d in json.loads(r.stdout)["blockdevices"] for n in walk(d)
                      if n.get("type") in ("disk", "part") and (n.get("path") or "").startswith("/dev/nvme"))
    except (ValueError, KeyError, TypeError):
        nvme = []
    show("pvs", "-o", "pv_name,pv_uuid,vg_name,vg_uuid,pv_size,dev_size")
    show("vgs", "-o", "vg_name,vg_uuid,pv_count,lv_count,vg_size,vg_free")
    show("lvs", "-a", "-o", "vg_name,vg_uuid,lv_name,lv_uuid,lv_size,lv_attr,devices")
    if nvme:
        show("pvs", "--devices", ",".join(nvme), "-o", "pv_name,pv_uuid,vg_name,vg_uuid,pv_size")
        show("lvs", "-a", "--devices", ",".join(nvme), "-o", "vg_name,vg_uuid,lv_name,lv_uuid,lv_size,devices")
    for p in nvme:
        show("wipefs", "--no-act", p)
        show("blkid", "-p", p)
    show("dmsetup", "info", "-c", "-o", "name,uuid,open,major,minor")
    show("swapon", "--show")
    show("findmnt", "-o", "TARGET,SOURCE,FSTYPE", "-t", "xfs,vfat,ext4,nfs4")
    show("efibootmgr", "-v")
    show("lvmdevices")
    try:
        with open(DEVICES_FILE) as fh:
            text = fh.read()
    except OSError as exc:
        text = "(%s)\n" % exc
    out.append("\n########## %s\n%s" % (DEVICES_FILE, text))
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--disk", action="append", default=[], metavar="SERIAL=EUI")
    ap.add_argument("--os-wwn")
    ap.add_argument("--model")
    ap.add_argument("--size", type=int)
    ap.add_argument("--legacy-vg")
    ap.add_argument("--legacy-lvs")
    ap.add_argument("--verify-after", metavar="PLAN.json")
    ap.add_argument("--unfinished", metavar="DIR")
    args = ap.parse_args()
    if args.record:
        sys.stdout.write(record())
        return 0
    if args.unfinished:
        print(json.dumps(unfinished(args.unfinished), sort_keys=True))
        return 0
    require(len(args.disk) == 2 and all(d.count("=") == 1 for d in args.disk), "exactly two --disk SERIAL=EUI")
    args.disk = [tuple(d.split("=")) for d in args.disk]
    for s, e in args.disk:
        require(SERIAL.match(s) and EUI.match(e), "malformed --disk %s=%s" % (s, e))
    require(len({s for s, _ in args.disk}) == 2 and len({e for _, e in args.disk}) == 2, "the two disks must differ")
    require(WWN.match(args.os_wwn or ""), "malformed --os-wwn")
    require(args.model and args.size and re.match(r"^[A-Za-z0-9_]+$", args.legacy_vg or ""), "missing --model/--size/--legacy-vg")
    args.legacy_lvs = [x for x in (args.legacy_lvs or "").split(",") if x]
    require(args.legacy_lvs, "missing --legacy-lvs")
    if args.verify_after:
        with open(args.verify_after) as fh:
            result = verify(args, json.load(fh))
    else:
        result = plan(args)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        verb = "NVME WIPE VERIFY FAILED" if "--verify-after" in sys.argv else "NVME WIPE REFUSED"
        print("%s: %s" % (verb, exc), file=sys.stderr)
        sys.exit(1)
