#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
"""The mirror of the package probe (cargo xtask pkg-probe): the files of a
repository over https, from a directory, on 127.0.0.1, with a certificate of
the probe CA. The guest of QEMU's user network reaches the host as 10.0.2.2.

Every response is one line of the log on standard output, flushed at once, for
xtask to read:

    pkg-mirror: GET /0.2/aarch64/INDEX 200 1234

(the method, the path, the status, the length of the body that was announced).
A server that is ready says `pkg-mirror: listening <port>`.

The server follows symbolic links, so that xtask changes the state of the
repository between two steps of the probe by changing one link. It takes
TLS 1.2 and above. It runs until it is killed: xtask starts it for the length
of one run of the probe and ends it with the run.
"""

import argparse
import functools
import http.server
import socketserver
import ssl
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    server_version = "pkg-mirror"
    sys_version = ""

    def __init__(self, *args, **kwargs):
        self.announced = "-"
        super().__init__(*args, **kwargs)

    def send_header(self, keyword, value):
        if keyword.lower() == "content-length":
            self.announced = value
        super().send_header(keyword, value)

    def end_headers(self):
        # The line is written when the headers go, before a long body.
        print(
            f"pkg-mirror: {self.command} {self.path} {self.last_code} {self.announced}",
            flush=True,
        )
        super().end_headers()

    def send_response(self, code, message=None):
        self.last_code = code
        super().send_response(code, message)

    def log_message(self, fmt, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind asks the resolver for the name of the host, which
        # takes tens of seconds on a machine whose resolver is slow for 127.0.0.1.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address):
        # A client that leaves in the handshake (curl that does not trust the
        # certificate) is a normal thing here.
        pass


def make(directory, port, cert, key, host="127.0.0.1"):
    handler = functools.partial(Handler, directory=directory)
    server = Server((host, port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    server = make(args.dir, args.port, args.cert, args.key)
    print(f"pkg-mirror: listening {args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
