#!/usr/bin/env python3
"""Temporary, IP-restricted single-ISO HTTP server; Python 3.6 or later.

Serve only /rocky.iso. Keep the file unchanged while this server is running.
This provides no TLS or authentication beyond a source-IP allowlist: use only
on the private BMC network, with a matching firewall rule, and stop after use.
"""

import argparse
import ipaddress
import os
import re
import socket
import stat
import sys
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def byte_range(value, size):
    """Return one inclusive byte range, None to ignore, or raise ValueError.

    Unknown units and multiple ranges are ignored (send the entire file).
    A malformed or unsatisfiable single bytes range receives HTTP 416.
    """
    if not value or not value.startswith("bytes=") or "," in value:
        return None
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value.strip())
    if not match or not any(match.groups()) or size == 0:
        raise ValueError("invalid range")
    first, last = match.groups()
    if not first:
        count = int(last)
        if count == 0:
            raise ValueError("empty suffix")
        return (max(0, size - count), size - 1)
    start = int(first)
    end = int(last) if last else size - 1
    if start >= size or end < start:
        raise ValueError("unsatisfiable range")
    return (start, min(end, size - 1))


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SingleISO/1"
    sys_version = ""

    def log_message(self, message, *args):
        # Never log request targets, headers, file contents, or credentials.
        pass

    def log_request(self, code="-", size="-"):
        sys.stderr.write("{} peer={} status={}\n".format(
            formatdate(usegmt=True), self.client_address[0], code))
        sys.stderr.flush()

    def empty(self, code, headers=None):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True

    def do_HEAD(self):
        self.serve_file(head=True)

    def do_GET(self):
        self.serve_file(head=False)

    def serve_file(self, head):
        self.connection.settimeout(60)
        peer = ipaddress.ip_address(self.client_address[0])
        if peer not in self.server.allowed:
            self.empty(403)
            return
        if self.path != "/rocky.iso":
            self.empty(404)
            return
        try:
            stream = open(self.server.iso_path, "rb")
        except OSError:
            self.empty(503)
            return
        with stream:
            info = os.fstat(stream.fileno())
            if identity(info) != self.server.iso_identity:
                self.empty(503)
                return
            size = info.st_size
            modified = formatdate(info.st_mtime, usegmt=True)
            etag = '"{:x}-{:x}"'.format(info.st_mtime_ns, size)
            requested = self.headers.get("Range") if not head else None
            if_range = self.headers.get("If-Range")
            if if_range and if_range not in (etag, modified):
                requested = None
            try:
                selected = byte_range(requested, size)
            except ValueError:
                self.empty(416, {"Content-Range": "bytes */{}".format(size),
                                 "Accept-Ranges": "bytes"})
                return
            start, end = selected if selected else (0, size - 1)
            length = max(0, end - start + 1)
            self.send_response(206 if selected else 200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Last-Modified", modified)
            self.send_header("ETag", etag)
            if selected:
                self.send_header("Content-Range", "bytes {}-{}/{}".format(
                    start, end, size))
            self.end_headers()
            if head:
                return
            stream.seek(start)
            remaining = length
            try:
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    if not block:
                        self.close_connection = True
                        break
                    self.wfile.write(block)
                    remaining -= len(block)
            except (OSError, socket.timeout):
                self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, help="ISO file to serve")
    parser.add_argument("--bind", required=True, type=ipaddress.ip_address,
                        help="specific local interface IP, not a wildcard")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--allow-client", required=True, action="append",
                        type=ipaddress.ip_address, help="allowed BMC source IP")
    args = parser.parse_args()
    if args.bind.is_unspecified:
        parser.error("--bind must be a specific interface IP")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    iso_path = os.path.realpath(args.file)
    try:
        with open(iso_path, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                parser.error("--file must be a regular file")
    except OSError:
        parser.error("--file is not readable")
    if args.bind.version == 6:
        Server.address_family = socket.AF_INET6
    server = Server((str(args.bind), args.port), Handler)
    server.iso_path = iso_path
    server.iso_identity = identity(info)
    server.allowed = frozenset(args.allow_client)
    print("Serving /rocky.iso on {}:{}; Ctrl-C stops the server.".format(
        args.bind, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
