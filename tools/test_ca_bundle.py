#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""The checks of tools/build-ca-bundle.py on bundles made here: the count of
certificates, the date of the header, the SHA-256, and the notice that
tools/dist.py takes from the header of a source that is one file."""

from hashlib import sha256
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("build_ca_bundle", HERE / "build-ca-bundle.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
spec = importlib.util.spec_from_file_location("dist", HERE / "dist.py")
dist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dist)

BLOCK = b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n"


def bundle(count: int, date: str = "Tue Oct 20 13:32:40 2026 GMT") -> bytes:
    head = (b"##\n## Bundle of CA Root Certificates\n##\n"
            b"## Certificate data from Mozilla as of: " + date.encode() + b"\n##\n\n")
    return head + b"".join(b"Root %d\n=======\n" % n + BLOCK + b"\n" for n in range(count))


class BundleTests(unittest.TestCase):
    def test_the_blocks_are_counted(self):
        self.assertEqual(builder.certificates(bundle(118)), 118)
        self.assertEqual(builder.certificates(b""), 0)

    def test_the_date_of_the_header(self):
        self.assertEqual(builder.header_date(bundle(1)), "2026-10-20")
        self.assertEqual(builder.header_date(bundle(1, "Tue Jan  2 03:12:01 2024 GMT")),
                         "2024-01-02")
        self.assertIsNone(builder.header_date(b"## no date\n"))

    def test_a_good_bundle_passes(self):
        data = bundle(118)
        builder.check(data, sha256(data).hexdigest(), "2026-10-20")

    def test_a_changed_byte_fails_the_sha256(self):
        data = bundle(118)
        good = sha256(data).hexdigest()
        at = data.index(b"MIIB")
        broken = data[:at] + b"N" + data[at + 1:]
        with self.assertRaisesRegex(SystemExit, "SHA-256"):
            builder.check(broken, good, "2026-10-20")

    def test_too_few_certificates_or_another_date_fail(self):
        data = bundle(builder.MIN_CERTIFICATES - 1)
        with self.assertRaisesRegex(SystemExit, "fewer than"):
            builder.check(data, sha256(data).hexdigest(), "2026-10-20")
        data = bundle(118)
        with self.assertRaisesRegex(SystemExit, "header is of 2026-10-20"):
            builder.check(data, sha256(data).hexdigest(), "2026-11-01")

    def test_the_notice_of_a_source_of_one_file_is_its_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cacert-2026-10-20.pem"
            path.write_bytes(bundle(3))
            texts = dist.license_texts(path)
            self.assertEqual(list(texts), ["cacert.pem.NOTICE"])
            self.assertTrue(texts["cacert.pem.NOTICE"].startswith(b"##\n## Bundle"))
            self.assertNotIn(b"BEGIN CERTIFICATE", texts["cacert.pem.NOTICE"])
            self.assertEqual(builder.header(bundle(3)), texts["cacert.pem.NOTICE"])


if __name__ == "__main__":
    unittest.main()
