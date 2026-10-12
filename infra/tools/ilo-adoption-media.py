#!/usr/bin/env python3
"""Scoped HPE fleet Redfish media helper; no mutation without --apply.

Use a verified SSH tunnel. --insecure disables TLS authentication: the tunnel
and serial check are useful controls, but are not certificate authentication.
Older iLO releases without advertised standard actions intentionally fail closed.
"""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

# Fixed local tunnels from docs/runbooks/MONDAY-RUNBOOK-2026-09-28.md. The login node's
# profile name is hpe; its iLO credential is distinct and must be named by caller.
NODES = {"g003": ("EXSERIAL03", "https://127.0.0.1:18449"),
         "g004": ("EXSERIAL04", "https://127.0.0.1:18450"),
         "g005": ("EXSERIAL05", "https://127.0.0.1:18443"),
         "hpe": ("EXSERIAL01", "https://127.0.0.1:18451")}


# The only BIOS attributes this tool may change, and their allowed values. Reading is allowed
# for these attributes only as well. D39 (28 Sep): all three V100 nodes on the HPC workload
# profile with Sub-NUMA Clustering off. The profile controls SNC under the two earlier profiles
# (it is ReadOnly there) but not under HPC, so g005 needs both. The earlier profiles stay
# allowed only as the recorded rollback values (g003 and g005 before the change).
BIOS_CHANGES = {"SubNumaClustering": ("Enabled", "Disabled"),
                "WorkloadProfile": ("HighPerformanceCompute(HPC)", "GeneralPowerEfficientCompute",
                                    "Virtualization-MaxPerformance")}


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def iso_url(value):
    require(not any(ord(c) < 32 for c in (value or "")), "Control characters in ISO URL.")
    p = urllib.parse.urlsplit(value or "")
    require(p.scheme in ("http", "https") and p.hostname and not p.username
            and not p.password and not p.query and not p.fragment,
            "ISO URL must be HTTP(S), with no credentials, query or fragment.")
    host = p.hostname.lower().rstrip(".")
    require(host != "localhost" and not host.endswith(".localhost"),
            "ISO URL must be reachable by iLO, not localhost.")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        require(not all(c in "0123456789." for c in host), "Noncanonical numeric ISO host.")
        addr = None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    require(addr is None or not (addr.is_loopback or addr.is_unspecified),
            "ISO URL must not use a loopback/unspecified address.")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("HTTP redirect refused; credentials were not forwarded.")


class Client:
    def __init__(self, base, user, password_file, insecure=False, ca_file=None):
        self.base = base
        path = Path(password_file).expanduser()
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) and not mode & 0o077,
                "Password file must be a regular owner-only file (0600).")
        password = path.read_text().rstrip("\r\n")
        require(password and "\n" not in password and "\r" not in password,
                "Password file must contain one nonempty line.")
        token = base64.b64encode((user + ":" + password).encode()).decode()
        self.authorization = "Basic " + token
        context = ssl.create_default_context(cafile=ca_file)
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirect())

    def request(self, method, path, payload=None):
        url = urllib.parse.urljoin(self.base, path)
        p, base = urllib.parse.urlsplit(url), urllib.parse.urlsplit(self.base)
        require((p.scheme, p.netloc) == (base.scheme, base.netloc)
                and p.path.startswith("/redfish/") and not p.query
                and not p.fragment, "Redfish link leaves the configured origin.")
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": self.authorization, "Accept": "application/json",
            "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read(2 * 1024 * 1024)
                require(response.status != 202,
                        "Operation accepted asynchronously; inspect status before any retry.")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            raise Refused("Redfish request returned HTTP %s; response body withheld."
                          % error.code) from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Refused("Redfish connection/TLS/JSON failure; no automatic retry.") from None


def members(client, link):
    collection = client.request("GET", link)
    require(not collection.get("contributor@example.org"),
            "Paginated discovery is unsupported; select the endpoint manually.")
    return [(x["@odata.id"], client.request("GET", x["@odata.id"]))
            for x in collection.get("Members", [])]


def discover(client, serial):
    root = client.request("GET", "/redfish/v1/")
    systems = members(client, root["Systems"]["@odata.id"])
    require(len(systems) == 1, "Expected exactly one system; discovery ambiguous.")
    system_path, system = systems[0]
    require(system.get("SerialNumber") == serial, "System serial mismatch; stopped.")
    managers = members(client, root["Managers"]["@odata.id"])
    require(len(managers) == 1, "Expected exactly one manager; discovery ambiguous.")
    manager = managers[0][1]
    require("VirtualMedia" in manager, "No advertised VirtualMedia collection.")
    media = members(client, manager["VirtualMedia"]["@odata.id"])
    optical = [(p, m) for p, m in media
               if {"CD", "DVD"}.intersection(m.get("MediaTypes", []))]
    require(len(optical) == 1, "Expected exactly one CD/DVD slot; absent or ambiguous.")
    return system_path, system, optical[0][0], optical[0][1]


def action(resource, name):
    item = resource.get("Actions", {}).get(name)
    require(isinstance(item, dict) and item.get("target"),
            "Required standard action is not advertised: " + name)
    return item


def allowed(client, item, parameter):
    values = item.get(parameter + "@Redfish.AllowableValues")
    if values is None and item.get("@Redfish.ActionInfo"):
        info = client.request("GET", item["@Redfish.ActionInfo"])
        values = next((p.get("AllowableValues") for p in info.get("Parameters", [])
                       if p.get("Name") == parameter), None)
    return values or []


def execute(client, node, command, apply=False, expected_iso=None, attribute=None, value=None):
    require(command in ("status", "bios-get") or apply,
            "Mutation refused without --apply; no BMC request was made.")
    if command in ("bios-get", "bios-set"):
        require(attribute in BIOS_CHANGES, "BIOS attribute not on this tool's allowlist.")
        require(command == "bios-get" or value in BIOS_CHANGES[attribute],
                "BIOS value not allowed for this attribute.")
    expected = iso_url(expected_iso) if expected_iso is not None else None
    require(command not in ("attach", "arm") or expected,
            "attach/arm require --iso-url for exact media readback.")
    serial = NODES[node][0]
    system_path, system, media_path, media = discover(client, serial)

    def mutate(method, target, payload):
        fresh = client.request("GET", system_path)
        require(fresh.get("SerialNumber") == serial,
                "System serial changed before mutation; stopped.")
        return client.request(method, target, payload)

    if command == "attach":
        require(not media.get("Inserted"),
                "Media already inserted; inspect and explicitly eject first.")
        item = action(media, "#VirtualMedia.InsertMedia")
        mutate("POST", item["target"], {"Image": expected, "Inserted": True,
                                       "WriteProtected": True})
        media = client.request("GET", media_path)
        require(media.get("Inserted") is True and media.get("Image") == expected,
                "Insert readback not confirmed; inspect status, do not arm.")
    elif command == "arm":
        require(media.get("Inserted") is True and media.get("Image") == expected,
                "Inserted media does not match --iso-url; boot not armed.")
        boot = system.get("Boot", {})
        change = {"BootSourceOverrideEnabled": "Once",
                  "BootSourceOverrideTarget": "Cd", "BootSourceOverrideMode": "UEFI"}
        missing = [k + "=" + v for k, v in change.items()
                   if v not in boot.get(k + "@Redfish.AllowableValues", [])]
        hpe_once = "BootOnNextServerReset" in media.get("Oem", {}).get("Hpe", {})
        if missing and hpe_once and boot.get("BootSourceOverrideMode") == "UEFI" \
                and "Cd" in boot.get("contributor@example.org", []):
            # iLO 5 lists no BootSourceOverrideEnabled values. Its one-time boot from this
            # virtual CD is the media's own flag (the iLO CLI's Boot_Once, used for g005 on
            # 22 Sep), consumed by the next server reset. The system stays in UEFI mode.
            mutate("PATCH", media_path, {"Oem": {"Hpe": {"BootOnNextServerReset": True}}})
            media = client.request("GET", media_path)
            require(media.get("Inserted") is True and media.get("Image") == expected,
                    "Media changed during boot arming; inspect status before powering/restarting.")
            require(media.get("Oem", {}).get("Hpe", {}).get("BootOnNextServerReset") is True,
                    "One-time virtual-media boot readback not confirmed; inspect status.")
        else:
            require(not missing, "Missing advertised boot value: " + ", ".join(missing))
            mutate("PATCH", system_path, {"Boot": change})
            system = client.request("GET", system_path)
            media = client.request("GET", media_path)
            require(media.get("Inserted") is True and media.get("Image") == expected,
                    "Media changed during boot arming; inspect status before powering/restarting.")
            require(all(system.get("Boot", {}).get(k) == v for k, v in change.items()),
                    "Boot readback not confirmed; inspect status before powering/restarting.")
    elif command == "eject":
        item = action(media, "#VirtualMedia.EjectMedia")
        mutate("POST", item["target"], {})
        media = client.request("GET", media_path)
        require(media.get("Inserted") is False, "Eject readback not confirmed.")
    elif command in ("bios-get", "bios-set"):
        # Pending BIOS settings apply at the next reboot; the caller reboots and re-reads.
        bios_link = system.get("Bios", {}).get("@odata.id")
        require(bios_link, "No advertised BIOS resource.")
        bios = client.request("GET", bios_link)
        current = bios.get("Attributes", {}).get(attribute)
        require(current is not None, "BIOS attribute not present on this system.")
        settings_link = bios.get("@Redfish.Settings", {}).get("SettingsObject", {}).get("@odata.id")
        require(settings_link, "No advertised BIOS settings object.")
        pending = client.request("GET", settings_link).get("Attributes", {}).get(attribute)
        if command == "bios-set":
            mutate("PATCH", settings_link, {"Attributes": {attribute: value}})
            pending = client.request("GET", settings_link).get("Attributes", {}).get(attribute)
            require(pending == value, "Pending BIOS value readback not confirmed; inspect before rebooting.")
        return {"node": node, "serial": serial, "attribute": attribute, "current": current,
                "pending": pending, "applies": "at the next reboot" if pending != current else "already in effect"}
    elif command in ("power-on", "restart", "shutdown"):
        # shutdown = a momentary power-button press: the OS shuts down cleanly (ACPI). With
        # power-on afterwards it is the graceful restart on iLOs without GracefulRestart.
        power, reset = {"power-on": ("Off", "On"), "restart": ("On", "GracefulRestart"),
                        "shutdown": ("On", "PushPowerButton")}[command]
        require(system.get("PowerState") == power, "Unexpected power state; stopped.")
        item = action(system, "#ComputerSystem.Reset")
        require(reset in allowed(client, item, "ResetType"),
                "Requested reset type is not advertised; no fallback.")
        mutate("POST", item["target"], {"ResetType": reset})
        return {"node": node, "serial": serial, "reset_requested": reset,
                "completion": "not verified; inspect status/console"}
    return {"node": node, "serial": serial, "power": system.get("PowerState"),
            "media_id": media.get("Id"), "inserted": media.get("Inserted"),
            "expected_image_match": media.get("Image") == expected if expected else None,
            "boot_on_next_reset": media.get("Oem", {}).get("Hpe", {}).get("BootOnNextServerReset"),
            "boot": {k: system.get("Boot", {}).get(k) for k in (
                "BootSourceOverrideEnabled", "BootSourceOverrideTarget", "BootSourceOverrideMode")},
            "standard_media_actions": [k for k in media.get("Actions", {})
                                       if k in ("#VirtualMedia.InsertMedia", "#VirtualMedia.EjectMedia")]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", choices=NODES)
    parser.add_argument("command", choices=("status", "attach", "arm", "eject", "power-on", "restart", "shutdown",
                                             "bios-get", "bios-set"))
    parser.add_argument("--attribute", help="bios-get/bios-set: a BIOS attribute on the allowlist")
    parser.add_argument("--value", help="bios-set: the new value (allowlisted)")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--iso-url")
    parser.add_argument("--user", default="hpadmin")
    # No default: every call names its node's own 0600 file (no implicit fleet credential).
    parser.add_argument("--password-file", required=True,
                        help="this node's BMC password file (0600); required, no default")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true")
    tls.add_argument("--ca-file")
    args = parser.parse_args()
    try:
        require(args.command in ("status", "bios-get") or args.apply,
                "Mutation refused without --apply; credentials were not read.")
        if args.iso_url is not None:
            iso_url(args.iso_url)
        client = Client(NODES[args.node][1], args.user, args.password_file,
                        args.insecure, args.ca_file)
        print(json.dumps(execute(client, args.node, args.command, args.apply, args.iso_url,
                                 args.attribute, args.value), indent=2))
    except (Refused, OSError, KeyError, TypeError, ValueError) as error:
        message = str(error) if isinstance(error, Refused) else "Local file or Redfish schema failure; details withheld."
        print("ERROR: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
