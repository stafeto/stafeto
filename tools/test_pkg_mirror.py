#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
"""Test of tools/pkg-mirror.py: the server on a free port with a certificate made
here, a download with the certificate as the only authority, the length and the
bytes, the line of the log, a state changed by a link, a client that does not
trust the certificate, and the end of the server with its process."""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MIRROR = os.path.join(HERE, "pkg-mirror.py")

CONFIG = """\
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = pkg-mirror-test
[ext]
subjectAltName = IP:127.0.0.1
basicConstraints = critical,CA:FALSE
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MirrorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("openssl is needed for the certificate")
        cls.tmp = tempfile.mkdtemp(prefix="pkg-mirror-test-")
        cnf = os.path.join(cls.tmp, "c.cnf")
        with open(cnf, "w") as f:
            f.write(CONFIG)
        cls.cert = os.path.join(cls.tmp, "c.crt")
        cls.key = os.path.join(cls.tmp, "c.key")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-nodes", "-config", cnf,
             "-keyout", cls.key, "-out", cls.cert, "-days", "2"],
            check=True, capture_output=True,
        )
        cls.www = os.path.join(cls.tmp, "www")
        for state, body in (("one", b"state one\n"), ("two", b"state two, longer\n")):
            os.makedirs(os.path.join(cls.tmp, "states", state))
            with open(os.path.join(cls.tmp, "states", state, "INDEX"), "wb") as f:
                f.write(body)
        os.makedirs(os.path.join(cls.www, "0.2"))
        cls.link = os.path.join(cls.www, "0.2", "aarch64")
        cls.point("one")
        cls.big = os.urandom(300_000)
        with open(os.path.join(cls.tmp, "states", "one", "big.bin"), "wb") as f:
            f.write(cls.big)

    @classmethod
    def point(cls, state):
        temp = cls.link + ".new"
        if os.path.lexists(temp):
            os.remove(temp)
        os.symlink(os.path.join(cls.tmp, "states", state), temp)
        os.replace(temp, cls.link)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def start(self, *extra):
        port = free_port()
        child = subprocess.Popen(
            [sys.executable, MIRROR, "--dir", self.www, "--port", str(port),
             "--cert", self.cert, "--key", self.key, *extra],
            stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(self.stop, child)
        line = child.stdout.readline().strip()
        self.assertEqual(line, f"pkg-mirror: listening {port}")
        return child, port

    @staticmethod
    def stop(child):
        child.kill()
        child.wait()
        child.stdout.close()

    def fetch(self, port, path, cafile=None):
        context = ssl.create_default_context(cafile=cafile or self.cert)
        url = f"https://127.0.0.1:{port}{path}"
        with urllib.request.urlopen(url, context=context, timeout=20) as r:
            return r.status, r.headers.get("Content-Length"), r.read()

    def test_a_file_comes_with_its_length_and_a_line_of_the_log(self):
        child, port = self.start()
        status, length, body = self.fetch(port, "/0.2/aarch64/INDEX")
        self.assertEqual((status, length, body), (200, "10", b"state one\n"))
        self.assertEqual(
            child.stdout.readline().strip(), "pkg-mirror: GET /0.2/aarch64/INDEX 200 10"
        )
        status, length, body = self.fetch(port, "/0.2/aarch64/big.bin")
        self.assertEqual((status, length, body), (200, "300000", self.big))
        self.assertEqual(
            child.stdout.readline().strip(), "pkg-mirror: GET /0.2/aarch64/big.bin 200 300000"
        )

    def test_a_listed_path_is_answered_302_and_the_client_follows_it(self):
        table = os.path.join(self.tmp, "redirects")
        with open(table, "w") as f:
            f.write("/moved/INDEX /0.2/aarch64/INDEX\n")
        child, port = self.start("--redirects", table)
        # urllib follows the redirect: the body is the file at the target.
        status, length, body = self.fetch(port, "/moved/INDEX")
        self.assertEqual((status, body), (200, b"state one\n"))
        self.assertEqual(child.stdout.readline().strip(), "pkg-mirror: GET /moved/INDEX 302 0")
        self.assertEqual(
            child.stdout.readline().strip(), "pkg-mirror: GET /0.2/aarch64/INDEX 200 10"
        )
        # The table is read at each request: a line added later counts, a path not in it is served as ever.
        with open(table, "a") as f:
            f.write("/also /0.2/aarch64/INDEX\n")
        self.assertEqual(self.fetch(port, "/also")[2], b"state one\n")
        self.assertEqual(self.fetch(port, "/0.2/aarch64/INDEX")[0], 200)

    def test_a_missing_file_is_a_404_in_the_log(self):
        child, port = self.start()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch(port, "/0.2/aarch64/none")
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()
        line = child.stdout.readline().strip()
        self.assertTrue(line.startswith("pkg-mirror: GET /0.2/aarch64/none 404 "), line)

    def test_a_link_changes_the_state_between_two_requests(self):
        child, port = self.start()
        try:
            self.assertEqual(self.fetch(port, "/0.2/aarch64/INDEX")[2], b"state one\n")
            self.point("two")
            self.assertEqual(
                self.fetch(port, "/0.2/aarch64/INDEX")[2], b"state two, longer\n"
            )
        finally:
            self.point("one")

    def test_a_client_that_does_not_trust_the_certificate_is_refused_by_itself(self):
        child, port = self.start()
        with self.assertRaises(urllib.error.URLError):
            context = ssl.create_default_context()
            urllib.request.urlopen(
                f"https://127.0.0.1:{port}/0.2/aarch64/INDEX", context=context, timeout=20
            )
        # The server is alive, and the next client that trusts it is served.
        self.assertEqual(self.fetch(port, "/0.2/aarch64/INDEX")[0], 200)

    def test_tls_1_1_is_refused(self):
        child, port = self.start()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            self.skipTest("this OpenSSL does not offer TLS 1.1")
        with self.assertRaises(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=20) as raw:
                with context.wrap_socket(raw):
                    pass

    def test_the_server_ends_with_the_signal_that_kills_it(self):
        child, port = self.start()
        child.kill()
        child.wait()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=2).close()


if __name__ == "__main__":
    unittest.main()
