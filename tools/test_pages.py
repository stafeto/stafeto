#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Tests of tools/pages.py on a local bare repository standing for
stafeto/packages. The signature is judged by `cargo xtask repo resign`
(tests of xtask: a wrong signature, a leaked key, a rollback, the 35 days of
the certificate); here the stand-in for it writes `sig:<sha256>` and refuses
a signature that is not that, so the tests show what the script does around
the signing: what it signs, in which order, what it writes and when it writes
nothing."""

import datetime
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pages  # noqa: E402

FAR = "2099-01-01T00:00:00Z"
SOON = "2000-01-01T00:00:00Z"
STORAGE = "v0.3.0-aarch64"
PREFIX = f"{pages.STORAGE}/{STORAGE}/"

# The stand-in for `cargo xtask repo resign`: the same arguments and the same
# refusals in the form that the test needs.
STUB = r'''
import hashlib, re, sys
args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
text = open(args["--index"]).read()
sig = open(args["--index"] + ".sig", "rb").read()
records = lambda t: t.split("\n\n", 1)[1]
anchor = open(args["--anchor"]).read()
if records(text) != records(anchor):
    print("the records of the index are not those of the signed copy")
    sys.exit(1)
if sig != b"sig:" + hashlib.sha256(text.encode()).hexdigest().encode():
    print("INDEX.sig is not accepted")
    sys.exit(1)
text = re.sub(r"^serial .*$", "serial " + args["--serial"], text, count=1, flags=re.M)
text = re.sub(r"^expires .*$", "expires EXPIRES", text, count=1, flags=re.M)
import pathlib
out = pathlib.Path(args["--out"]); out.mkdir(parents=True, exist_ok=True)
(out / "INDEX").write_text(text)
open("LOG", "a").write("strict\n" if "--strict" in sys.argv else "plain\n")
(out / "INDEX.sig").write_bytes(b"sig:" + hashlib.sha256(text.encode()).hexdigest().encode())
'''


def signed(text: str) -> bytes:
    return b"sig:" + hashlib.sha256(text.encode()).hexdigest().encode()


def index(series="0.3", serial=5, expires=FAR, files=(("a", "a-1-1.stpkg", b"AAAA"),)) -> str:
    out = f"format 1\nrepository stafeto\nseries {series}\narch aarch64\nserial {serial}\nexpires {expires}\n"
    for name, file, data in files:
        out += (f"\nname {name}\nversion 1-1\nlicense MIT\nsize {len(data)}\n"
                f"sha256 {hashlib.sha256(data).hexdigest()}\nrecipe {'0' * 64}\nfile {PREFIX}{file}\n"
                f"source {PREFIX}{file[:-6]}-src.tar.xz\nsummary s\n")
    return out


def git(directory: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(directory), *args], capture_output=True, text=True, check=True).stdout


class Branch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.origin = self.dir / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "gh-pages", str(self.origin)], check=True)
        seed = self.dir / "seed"
        subprocess.run(["git", "init", "-q", "-b", "gh-pages", str(seed)], check=True)
        (seed / "README").write_text("pages\n")
        git(seed, "add", "-A")
        git(seed, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "start")
        git(seed, "push", "-q", str(self.origin), "gh-pages")
        self.stub = self.dir / "stub.py"
        self.log = self.dir / "calls.log"
        self.stub.write_text(STUB.replace("EXPIRES", FAR).replace("LOG", str(self.log)))
        self.command = f"{sys.executable} {self.stub}"
        self.revoked = self.dir / "keys"
        self.revoked.mkdir()
        (self.revoked / "revoked").write_text("list\n")
        (self.revoked / "revoked.sig").write_bytes(b"listsig")
        self.pages = self.dir / "pages"
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.pages)], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def release(self, text: str, signature: bytes | None = None) -> Path:
        directory = self.dir / "release"
        directory.mkdir(exist_ok=True)
        (directory / "INDEX").write_text(text)
        (directory / "INDEX.sig").write_bytes(signature if signature is not None else signed(text))
        return directory

    def publish(self, text: str, signature: bytes | None = None, version="0.3.0", others: dict | None = None) -> int:
        """Publishes `version` with the copy `text`; `others` maps the tags of other published
        releases to their copies."""
        series = ".".join(version.split(".")[:2])
        listing, files = self.releases(**{series.replace(".", "_"): text})
        listing[0]["tag_name"] = f"v{version}"
        base = f"{pages.RELEASES}/v{version}/stafeto-{version}-INDEX"
        listing[0]["assets"] = [{"name": f"stafeto-{version}-INDEX", "browser_download_url": base},
                                {"name": f"stafeto-{version}-INDEX.sig", "browser_download_url": base + ".sig"}]
        for tag, copy in (others or {}).items():
            more, extra = self.releases(**{".".join(tag[1:].split(".")[:2]).replace(".", "_"): copy})
            more[0]["tag_name"] = tag
            base = f"{pages.RELEASES}/{tag}/stafeto-{tag[1:]}-INDEX"
            more[0]["assets"] = [{"name": f"stafeto-{tag[1:]}-INDEX", "browser_download_url": base},
                                 {"name": f"stafeto-{tag[1:]}-INDEX.sig", "browser_download_url": base + ".sig"}]
            files[base] = copy.encode()
            listing += more
        return pages.publish(self.pages, version, self.release(text, signature), self.revoked, self.command, True,
                             listing, files.get)

    def remote(self, path: str) -> str:
        return git(self.origin, "show", f"gh-pages:{path}")

    def releases(self, **texts: str) -> tuple[list[dict], dict[str, bytes]]:
        """Releases of stafeto/stafeto holding the signed copies `texts` (series 0_3 as 0.3)."""
        listing, files = [], {}
        for series, text in texts.items():
            series = series.replace("_", ".")
            tag = f"v{series}.0"
            base = f"{pages.RELEASES}/{tag}/stafeto-{series}.0-INDEX"
            listing.append({"tag_name": tag, "draft": False, "prerelease": False, "assets": [
                {"name": f"stafeto-{series}.0-INDEX", "browser_download_url": base},
                {"name": f"stafeto-{series}.0-INDEX.sig", "browser_download_url": base + ".sig"}]})
            files[base], files[base + ".sig"] = text.encode(), signed(text)
        return listing, files

    def week(self, push=True, **texts: str) -> dict:
        listing, files = self.releases(**texts)
        return pages.weekly(self.pages, self.revoked, self.command, push, listing, self.dir / "anchors", get=files.__getitem__)

    def head(self) -> str:
        return git(self.origin, "rev-parse", "gh-pages").strip()

    def test_a_release_goes_to_the_branch_in_one_commit(self):
        serial = self.publish(index(serial=5))
        self.assertEqual(serial, 5)
        self.assertEqual(git(self.origin, "log", "-1", "--format=%s", "gh-pages").strip(), "publish 0.3.0: serial 5")
        self.assertEqual(git(self.origin, "log", "-1", "--format=%an <%ae>", "gh-pages").strip(),
                         "Sergey Subbotin <ssubbotin@gmail.com>")
        self.assertIn("serial 5", self.remote("0.3/aarch64/INDEX"))
        self.assertEqual(self.remote("0.3/aarch64/revoked"), "list\n")
        self.assertEqual(self.remote("series.txt"), "0.3\n")
        self.assertEqual(self.remote(".nojekyll"), "")
        self.assertEqual(len(git(self.origin, "rev-list", "gh-pages").split()), 2)

    def test_a_release_is_signed_with_the_list_judging_its_copy_and_the_week_is_not(self):
        self.publish(index(serial=5))
        self.week(push=False, **{"0_3": index(serial=5)})
        self.assertEqual(self.log.read_text().split(), ["strict", "plain"])

    def test_an_old_release_published_again_is_refused(self):
        self.publish(index(serial=5), version="0.3.1")
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.publish(index(serial=4), version="0.3.0", others={"v0.3.1": index(serial=5)})
        self.assertIn("not the newest", str(stopped.exception))
        self.assertEqual(self.head(), before)

    def test_an_older_copy_swapped_into_a_draft_is_refused(self):
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.publish(index(serial=5), version="0.3.1", others={"v0.3.0": index(serial=7)})
        self.assertIn("not above", str(stopped.exception))
        with self.assertRaises(SystemExit):
            self.publish(index(serial=7), version="0.3.1", others={"v0.3.0": index(serial=7)})
        self.assertEqual(self.head(), before)
        self.publish(index(serial=8), version="0.3.1", others={"v0.3.0": index(serial=7)})

    def test_a_copy_of_another_series_is_refused(self):
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.publish(index(series="0.4", serial=5), version="0.3.1")
        self.assertIn("series", str(stopped.exception))
        self.assertEqual(self.head(), before)

    def test_the_week_follows_the_same_checks(self):
        self.publish(index(serial=5))
        listing, files = self.releases(**{"0_3": index(serial=3)})
        more, extra = self.releases(**{"0_3": index(serial=9)})
        more[0]["tag_name"] = "v0.3.1"
        old, new = more[0]["assets"][0]["browser_download_url"], more[0]["assets"][1]["browser_download_url"]
        base = f"{pages.RELEASES}/v0.3.1/stafeto-0.3.1-INDEX"
        more[0]["assets"] = [{"name": "stafeto-0.3.1-INDEX", "browser_download_url": base},
                             {"name": "stafeto-0.3.1-INDEX.sig", "browser_download_url": base + ".sig"}]
        files[base], files[base + ".sig"] = index(serial=2).encode(), signed(index(serial=2))
        with self.assertRaises(SystemExit) as stopped:
            pages.weekly(self.pages, self.revoked, self.command, False, listing + more, self.dir / "anchors", get=files.__getitem__)
        self.assertIn("not above", str(stopped.exception))

    def test_the_serial_on_the_pages_goes_up_past_the_serial_of_the_release(self):
        self.publish(index(serial=5))
        # The copy of the release carries 3, the pages have 5: the next serial is 6.
        self.assertEqual(self.publish(index(serial=3), version="0.3.1"), 6)
        self.assertIn("serial 6", self.remote("0.3/aarch64/INDEX"))
        # A copy ahead of the pages keeps its own number.
        self.assertEqual(self.publish(index(serial=9), version="0.3.2"), 9)
        self.assertEqual(self.remote("series.txt"), "0.3\n")

    def test_a_second_series_is_added_to_the_list(self):
        self.publish(index(series="0.3"))
        self.publish(index(series="0.4"), version="0.4.0")
        self.assertEqual(self.remote("series.txt"), "0.3\n0.4\n")

    def test_an_index_with_a_wrong_signature_is_not_published(self):
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.publish(index(serial=5), signature=b"sig:forged")
        self.assertIn("not accepted", str(stopped.exception))
        self.assertEqual(self.head(), before)

    def test_the_weekly_job_signs_every_series_again_in_one_commit(self):
        self.publish(index(series="0.3", serial=5))
        self.publish(index(series="0.4", serial=7), version="0.4.0")
        done = self.week(**{"0_3": index(series="0.3", serial=5), "0_4": index(series="0.4", serial=7)})
        self.assertEqual(done, {"0.3": 6, "0.4": 8})
        self.assertIn("serial 6", self.remote("0.3/aarch64/INDEX"))
        self.assertIn("serial 8", self.remote("0.4/aarch64/INDEX"))
        self.assertEqual(git(self.origin, "log", "-1", "--format=%s", "gh-pages").strip(),
                         "resign 0.3: serial 6, 0.4: serial 8")

    def test_the_weekly_job_keeps_the_records_and_writes_the_list_again(self):
        self.publish(index(serial=5))
        records = self.remote("0.3/aarch64/INDEX").split("\n\n", 1)[1]
        (self.revoked / "revoked").write_text("list 2\n")
        self.week(**{"0_3": index(serial=5)})
        self.assertEqual(self.remote("0.3/aarch64/INDEX").split("\n\n", 1)[1], records)
        self.assertEqual(self.remote("0.3/aarch64/revoked"), "list 2\n")

    def test_one_series_with_a_wrong_signature_stops_the_week_and_writes_nothing(self):
        self.publish(index(series="0.3", serial=5))
        self.publish(index(series="0.4", serial=7), version="0.4.0")
        (self.pages / "0.4/aarch64/INDEX.sig").write_bytes(b"sig:forged")
        git(self.pages, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "lay a file")
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.week(**{"0_3": index(series="0.3", serial=5), "0_4": index(series="0.4", serial=7)})
        self.assertIn("0.4", str(stopped.exception))
        self.assertEqual(self.head(), before)
        # 0.3 was not written either.
        self.assertIn("serial 5", (self.pages / "0.3/aarch64/INDEX").read_text())

    def test_a_series_that_is_listed_and_missing_stops_the_week(self):
        (self.pages / "series.txt").write_text("0.3\n")
        with self.assertRaises(SystemExit) as stopped:
            self.week(push=False, **{"0_3": index(serial=5)})
        self.assertIn("0.3", str(stopped.exception))

    def test_a_term_under_14_days_stops_the_week(self):
        self.publish(index(serial=5))
        self.stub.write_text(STUB.replace("EXPIRES", SOON).replace("LOG", str(self.log)))
        with self.assertRaises(SystemExit) as stopped:
            self.week(push=False, **{"0_3": index(serial=5)})
        self.assertIn("14 days", str(stopped.exception))

    def test_an_old_signed_index_laid_into_the_pages_is_not_signed_again(self):
        self.publish(index(serial=5))
        old = index(serial=4, files=(("a", "a-1-1.stpkg", b"AAAA"), ("b", "b-1-1.stpkg", b"BB")))
        (self.pages / "0.3/aarch64/INDEX").write_text(old)
        (self.pages / "0.3/aarch64/INDEX.sig").write_bytes(signed(old))
        git(self.pages, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "lay an old index")
        before = self.head()
        with self.assertRaises(SystemExit) as stopped:
            self.week(**{"0_3": index(serial=5)})
        self.assertIn("not those of the signed copy", str(stopped.exception))
        self.assertEqual(self.head(), before)

    def test_a_series_that_no_release_carries_stops_the_week(self):
        self.publish(index(serial=5))
        with self.assertRaises(SystemExit) as stopped:
            self.week(push=False)
        self.assertIn("no published release", str(stopped.exception))

    def test_a_name_that_is_no_series_stops_the_week(self):
        (self.pages / "series.txt").write_text("0.3\n../../x\n")
        with self.assertRaises(SystemExit):
            self.week(push=False, **{"0_3": index()})

    def test_a_series_taken_off_the_list_is_not_signed_again(self):
        self.publish(index(series="0.3", serial=5))
        self.publish(index(series="0.4", serial=7), version="0.4.0")
        (self.pages / "series.txt").write_text("0.4\n")
        self.assertEqual(self.week(push=False, **{"0_4": index(series="0.4", serial=7)}), {"0.4": 8})
        self.assertIn("serial 5", (self.pages / "0.3/aarch64/INDEX").read_text())


class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.attachments = self.dir / "storage"
        self.attachments.mkdir()
        self.index = self.dir / "INDEX"
        self.index.write_text(index())
        (self.attachments / "a-1-1.stpkg").write_bytes(b"AAAA")
        (self.attachments / "a-1-1-src.tar.xz").write_bytes(b"source")

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self):
        return pages.verify_storage(self.index, STORAGE, self.attachments)

    def test_the_attachments_of_the_index_pass(self):
        self.assertEqual(self.verify(), 2)

    def test_an_attachment_that_changed_stops_the_publication(self):
        (self.attachments / "a-1-1.stpkg").write_bytes(b"BBBB")
        with self.assertRaises(SystemExit) as stopped:
            self.verify()
        self.assertIn("SHA-256", str(stopped.exception))

    def test_an_extra_attachment_stops_the_publication(self):
        (self.attachments / "evil.stpkg").write_bytes(b"x")
        with self.assertRaises(SystemExit) as stopped:
            self.verify()
        self.assertIn("evil.stpkg", str(stopped.exception))

    def test_a_missing_attachment_stops_the_publication(self):
        (self.attachments / "a-1-1.stpkg").unlink()
        with self.assertRaises(SystemExit) as stopped:
            self.verify()
        self.assertIn("lacks a-1-1.stpkg", str(stopped.exception))

    def test_the_addresses_answer_with_the_size_of_the_index(self):
        answers = {}
        seen = []

        def probe(url):
            seen.append(url)
            return answers.get(url, (200, 4 if url.endswith(".stpkg") else 99))

        self.assertEqual(pages.check_addresses(self.index, probe, pause=0), 2)
        answers[PREFIX + "a-1-1.stpkg"] = (200, 5)
        with self.assertRaises(SystemExit):
            pages.check_addresses(self.index, probe, attempts=2, pause=0)
        answers[PREFIX + "a-1-1.stpkg"] = (404, None)
        with self.assertRaises(SystemExit) as stopped:
            pages.check_addresses(self.index, probe, attempts=1, pause=0)
        self.assertIn("404", str(stopped.exception))


class NewFiles(unittest.TestCase):
    def test_the_carried_packages_stay_in_their_own_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "src").mkdir()
            for name in ("a-1-1.stpkg", "b-2-1.stpkg", "c-3-1.stpkg"):
                (d / name).write_bytes(b"x")
            (d / "src" / "a-1-1-src.tar.xz").write_bytes(b"s")
            (d / "src" / "b-2-1-src.tar.xz").write_bytes(b"s")
            (d / "carried.txt").write_text("b-2-1.stpkg\thttps://example.org/b-2-1.stpkg\t-\n")
            self.assertEqual([p.name for p in pages.new_files(d)],
                             ["a-1-1.stpkg", "a-1-1-src.tar.xz", "c-3-1.stpkg"])
            (d / "carried.txt").unlink()
            self.assertEqual(len(pages.new_files(d)), 5)


class Previous(unittest.TestCase):
    def tree(self, tmp: str, line: str | None) -> Path:
        tree = Path(tmp)
        (tree / "packages").mkdir(exist_ok=True)
        (tree / "keys").mkdir(exist_ok=True)
        (tree / "keys" / "revoked").write_text("list\n")
        (tree / "keys" / "revoked.sig").write_bytes(b"sig")
        if line is not None:
            (tree / "packages" / "published-serial.txt").write_text(line)
        return tree

    def releases(self):
        base = f"{pages.RELEASES}/v0.3.0/stafeto-0.3.0-INDEX"
        listing = [{"tag_name": "v0.3.0", "draft": False, "prerelease": False, "assets": [
            {"name": "stafeto-0.3.0-INDEX", "browser_download_url": base},
            {"name": "stafeto-0.3.0-INDEX.sig", "browser_download_url": base + ".sig"}]}]
        return listing, {base: index(serial=5).encode(), base + ".sig": b"sig"}

    def test_a_series_that_nobody_published_is_built_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            self.assertEqual(pages.previous("0.3", self.tree(tmp, None), lambda url: None, [], out), "")
            self.assertEqual(pages.previous("0.3", self.tree(tmp, "0.2 4\n"), lambda url: "0.2\n", [], out), "")

    def test_a_recorded_series_is_carried_from_the_signed_copy_of_its_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            listing, files = self.releases()
            out = Path(tmp) / "out"
            where = pages.previous("0.3", self.tree(tmp, "0.3 12\n"), lambda url: None, listing, out, files.__getitem__)
            self.assertEqual(where, str(out / "0.3"))
            self.assertEqual((out / "0.3" / "INDEX").read_text(), index(serial=5))
            self.assertEqual((out / "0.3" / "revoked").read_text(), "list\n")
            # A recorded series with no release that carries its index stops the build.
            with self.assertRaises(SystemExit):
                pages.previous("0.3", self.tree(tmp, "0.3 12\n"), lambda url: None, [], out)

    def test_a_series_on_the_pages_and_not_recorded_stops_the_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as stopped:
                pages.previous("0.3", self.tree(tmp, None), lambda url: "0.3\n", [], Path(tmp) / "o")
            self.assertIn("published-serial.txt", str(stopped.exception))

    def test_the_newest_final_release_of_a_series_is_the_anchor(self):
        def release(tag, **kw):
            base = f"{pages.RELEASES}/{tag}/stafeto-{tag[1:]}-INDEX"
            return {"tag_name": tag, "draft": False, "prerelease": False, **kw, "assets": [
                {"name": f"stafeto-{tag[1:]}-INDEX", "browser_download_url": base},
                {"name": f"stafeto-{tag[1:]}-INDEX.sig", "browser_download_url": base + ".sig"}]}
        found = pages.newest_copies([release("v0.3.0"), release("v0.3.2"), release("v0.3.10"),
                                     release("v0.3.11", draft=True), release("v0.4.0", prerelease=True),
                                     release("v0.4.0-pre.1"), release("v0.2.5")])
        self.assertEqual({s: v["tag"] for s, v in found.items()}, {"0.3": "v0.3.10", "0.2": "v0.2.5"})


class Gate(unittest.TestCase):
    def test_nothing_is_published_while_no_series_is(self):
        for event in ("schedule", "push", "workflow_dispatch"):
            go, reason = pages.gate(event, "false", "", [], lambda url: None)
            self.assertFalse(go, event)
            self.assertIn("no series is published", reason)
        self.assertFalse(pages.gate("schedule", "false", "", [], lambda url: "\n")[0])

    def test_a_network_error_is_not_the_absence_of_a_series(self):
        def broken(url):
            raise OSError("connection reset")
        with self.assertRaises(SystemExit) as stopped:
            pages.gate("schedule", "false", "", [], broken)
        self.assertIn("cannot be read", str(stopped.exception))

    def test_a_series_the_tree_records_and_the_pages_do_not_list_stops_the_run(self):
        with self.assertRaises(SystemExit):
            pages.gate("schedule", "false", "", [], lambda url: None, ("0.3",))

    def test_a_published_series_wakes_the_weekly_job(self):
        self.assertTrue(pages.gate("schedule", "false", "", [], lambda url: "0.3\n")[0])

    def test_a_pre_release_or_a_release_with_a_suffix_publishes_nothing(self):
        assets = ["stafeto-0.3.0-INDEX", "stafeto-0.3.0-INDEX.sig"]
        self.assertFalse(pages.gate("release", "true", "v0.3.0", assets, None)[0])
        self.assertFalse(pages.gate("release", "false", "v0.3.0-pre.1", assets, None)[0])

    def test_a_release_with_no_index_publishes_nothing(self):
        go, reason = pages.gate("release", "false", "v0.2.0", ["stafeto-0.2.0-sbom.spdx.json"], None)
        self.assertFalse(go)
        self.assertIn("no stafeto-0.2.0-INDEX", reason)

    def test_a_final_release_with_the_signed_index_is_published(self):
        assets = ["stafeto-0.3.0-INDEX", "stafeto-0.3.0-INDEX.sig", "SHA256SUMS"]
        self.assertTrue(pages.gate("release", "false", "v0.3.0", assets, None)[0])


if __name__ == "__main__":
    unittest.main()
