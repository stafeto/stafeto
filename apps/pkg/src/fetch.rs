// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The download (pk4-design R3): `pkg` runs `/bin/curl` as a child with the
//! options below, an environment that holds the proxy variables and nothing
//! else, and the standard output on a pipe. This module makes the command
//! line and the environment, and says in words what an end of the child
//! means; the program starts it and counts the bytes.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const CURL: &str = "/bin/curl";
/// The set of the certificate authorities, the file curl was built to use.
pub const CA_FILE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// The most an `INDEX` holds, `INDEX.sig` and `revoked.sig` (the block
/// `STAFSIG1`) and `revoked` (without its block): what curl is told to refuse
/// beyond.
pub const INDEX_MAX: u64 = 1 << 20;
pub const BLOCK_LEN: u64 = 456;
pub const REVOKED_MAX: u64 = 16 * 1024;

/// The variables of the environment of the parent that pass to curl.
const PASSED: [&str; 3] = ["https_proxy", "HTTPS_PROXY", "no_proxy"];

/// The command line of curl for `url`, which may answer `max` bytes at most.
/// `-q` comes first, so curl reads no `.curlrc` that could hold `-k` or another
/// `--cacert`; the scheme is https for the first request and for every
/// redirection; the certificates are checked against the file named here.
/// There is no time limit for the whole transfer (a game of 28 MB on a slow
/// line), only for a transfer that stalls: under 1 byte a second for 60 s.
pub fn argv(url: &str, max: u64) -> Vec<String> {
    let mut line: Vec<String> = [
        CURL,
        "-q",
        "-fsSL",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--cacert",
        CA_FILE,
        "--max-filesize",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    line.push(max.to_string());
    line.extend(
        [
            "--max-redirs",
            "5",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1",
            "--speed-time",
            "60",
            "-o",
            "-",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    line.push(url.to_string());
    line
}

/// The environment of curl, as `NAME=value` strings: the proxy variables the
/// parent has and no other, so that `CURL_CA_BUNDLE`, `SSL_CERT_FILE` and the
/// like change nothing about whom curl trusts.
pub fn environment<'a>(parent: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    parent
        .into_iter()
        .filter(|(name, _)| PASSED.contains(name))
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

/// What curl's end means, in the words of the line `pkg: <address>: <this>`.
/// `clock` is the time of the clock, which code 60 names: a wrong clock makes
/// a certificate fail before any index could be too old.
pub fn meaning(code: i32, clock: &str) -> String {
    match code {
        1 => "not https".into(),
        6 => "cannot resolve the host".into(),
        7 => "cannot connect".into(),
        22 => "the server answered with an error".into(),
        28 => "the transfer stalled".into(),
        35 => "the TLS handshake failed".into(),
        47 => "too many redirects".into(),
        56 => "the connection broke".into(),
        60 => format!("the certificate is not trusted (the clock says {clock})"),
        63 => "larger than the index says".into(),
        other => format!("curl failed with {other}"),
    }
}

/// How a download ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The bytes are what was asked, and curl ended with 0.
    Whole,
    /// The server sent more than the size.
    TooMany,
    /// curl ended with 0 and the server sent less than the size.
    Short(u64),
    /// curl ended with this code (it failed, or it was told to stop).
    Curl(i32),
}

/// The verdict on a download of `got` bytes that ended with `code`. `size` is
/// the exact length the bytes must have, when it is known (a package, a
/// signature block); more bytes than that are refused whatever curl said, and
/// fewer after a clean end are refused.
pub fn verdict(code: i32, got: u64, size: Option<u64>) -> Verdict {
    match size {
        Some(size) if got > size => Verdict::TooMany,
        _ if code != 0 => Verdict::Curl(code),
        Some(size) if got < size => Verdict::Short(got),
        _ => Verdict::Whole,
    }
}

/// The line for a download that was not whole: `url` is the address, `what`
/// the name the lengths are told of (a package, or the file), `size` its length.
pub fn failure(verdict: Verdict, url: &str, what: &str, size: u64, clock: &str) -> String {
    match verdict {
        Verdict::Whole => String::new(),
        Verdict::TooMany => format!("pkg: {what}: the server sent more than {size} bytes"),
        Verdict::Short(got) => format!("pkg: {what}: the server sent {got} of {size} bytes"),
        Verdict::Curl(code) => format!("pkg: {url}: {}", meaning(code, clock)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_is_the_whole_of_the_note() {
        let line = argv("https://10.0.2.2:8443/0.3/aarch64/INDEX", 1_048_576);
        assert_eq!(
            line.join(" "),
            "/bin/curl -q -fsSL --proto =https --proto-redir =https --tlsv1.2 \
             --cacert /etc/ssl/certs/ca-certificates.crt --max-filesize 1048576 \
             --max-redirs 5 --connect-timeout 30 --speed-limit 1 --speed-time 60 \
             -o - https://10.0.2.2:8443/0.3/aarch64/INDEX"
        );
        // -q is the first option; the address is the last word.
        assert_eq!(line[1], "-q");
        assert_eq!(
            line.last().unwrap(),
            "https://10.0.2.2:8443/0.3/aarch64/INDEX"
        );
        // The size is the package's, exactly.
        let pkg = argv("https://x.example/a.stpkg", 495_616);
        assert!(pkg.windows(2).any(|w| w == ["--max-filesize", "495616"]));
        assert!(!line.iter().any(|w| w == "-k" || w == "--insecure"));
    }

    #[test]
    fn curl_gets_the_proxy_variables_and_no_other() {
        let parent = [
            ("PATH", "/bin"),
            ("https_proxy", "http://p.example:3128"),
            ("CURL_CA_BUNDLE", "/tmp/mine.pem"),
            ("SSL_CERT_FILE", "/tmp/mine.pem"),
            ("HTTPS_PROXY", "http://q.example:3128"),
            ("no_proxy", "localhost"),
            ("http_proxy", "http://r.example"),
        ];
        assert_eq!(
            environment(parent),
            [
                "https_proxy=http://p.example:3128",
                "HTTPS_PROXY=http://q.example:3128",
                "no_proxy=localhost"
            ]
        );
        assert!(environment([("HOME", "/root")]).is_empty());
    }

    #[test]
    fn every_end_of_curl_has_its_words() {
        let clock = "2026-11-05T10:00:00Z";
        for (code, words) in [
            (1, "not https"),
            (6, "cannot resolve the host"),
            (7, "cannot connect"),
            (22, "the server answered with an error"),
            (28, "the transfer stalled"),
            (35, "the TLS handshake failed"),
            (47, "too many redirects"),
            (56, "the connection broke"),
            (
                60,
                "the certificate is not trusted (the clock says 2026-11-05T10:00:00Z)",
            ),
            (63, "larger than the index says"),
            (77, "curl failed with 77"),
            (-1, "curl failed with -1"),
        ] {
            assert_eq!(meaning(code, clock), words, "{code}");
        }
    }

    #[test]
    fn the_verdict_counts_the_bytes_and_the_code() {
        assert_eq!(verdict(0, 10, Some(10)), Verdict::Whole);
        assert_eq!(verdict(0, 10, None), Verdict::Whole);
        assert_eq!(verdict(0, 11, Some(10)), Verdict::TooMany);
        // More than the size is too many even when the child was killed for it.
        assert_eq!(verdict(143, 11, Some(10)), Verdict::TooMany);
        assert_eq!(verdict(0, 9, Some(10)), Verdict::Short(9));
        assert_eq!(verdict(56, 9, Some(10)), Verdict::Curl(56));
        assert_eq!(verdict(63, 0, Some(10)), Verdict::Curl(63));
        assert_eq!(verdict(22, 0, None), Verdict::Curl(22));
    }

    #[test]
    fn the_failure_lines() {
        let clock = "T";
        let u = "https://m.example/a.stpkg";
        assert_eq!(
            failure(Verdict::TooMany, u, "freedoom", 100, clock),
            "pkg: freedoom: the server sent more than 100 bytes"
        );
        assert_eq!(
            failure(Verdict::Short(40), u, "freedoom", 100, clock),
            "pkg: freedoom: the server sent 40 of 100 bytes"
        );
        assert_eq!(
            failure(Verdict::Curl(7), u, "freedoom", 100, clock),
            "pkg: https://m.example/a.stpkg: cannot connect"
        );
        assert_eq!(failure(Verdict::Whole, u, "x", 1, clock), "");
    }
}
