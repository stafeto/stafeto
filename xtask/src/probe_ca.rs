// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The certificate authority of the probes of TLS (`cargo xtask probe-ca
//! [--renew]`): `target/probe-ca/` with a CA, the certificates it signs for
//! the servers of the probes, a self-signed one that no CA knows, and the
//! root certificates of Mozilla with the CA added (`bundle-with-ca.crt`),
//! which the images of the probes carry as their CA file. The host's
//! `openssl` makes them (LibreSSL on macOS, OpenSSL on the runner), with
//! the options both know: the extensions come from a file of settings, and
//! the keys are EC P-256, whose handshake is cheap under TCG.
//!
//! * `ca.crt`: CN `stafeto probe CA`, a CA that signs certificates.
//! * `nginx.crt`: `DNS:nginx.stafeto.test`, `IP:127.0.0.1`, signed by the CA.
//! * `host-a.crt`: `DNS:host.stafeto.test`, `IP:10.0.2.2` (the host as the
//!   guest of QEMU's user network sees it), signed by the CA.
//! * `host-b.crt`: `IP:10.0.2.2`, self-signed: a CA nobody knows.
//!
//! Every certificate is valid for ten years from its making: the images live
//! in `target` for longer than days. The files are made when one of them is
//! missing; `--renew` makes them again. None of the keys goes into an image
//! of a release: only the images of the probes carry the CA.
//!
//! The certificates are checked against the guest's clock, so a probe first
//! compares the guest's time with the host's (`clock`).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The days a certificate is valid.
const DAYS: &str = "3650";
/// The guest's clock may be this far from the host's.
pub const CLOCK_SLACK_S: i64 = 600;

/// The settings of the certificates: the extensions of each.
const SETTINGS: &str = "\
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[nginx]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:nginx.stafeto.test,IP:127.0.0.1
[host_a]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:host.stafeto.test,IP:10.0.2.2
[host_b]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
subjectAltName = IP:10.0.2.2
";

/// The files of the directory.
pub const FILES: [&str; 9] = [
    "ca.key",
    "ca.crt",
    "nginx.key",
    "nginx.crt",
    "host-a.key",
    "host-a.crt",
    "host-b.key",
    "host-b.crt",
    "bundle-with-ca.crt",
];

/// The directory of the CA.
pub fn dir() -> PathBuf {
    crate::target_dir().join("probe-ca")
}

fn openssl(dir: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| format!("openssl is needed for the probe CA: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "openssl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Makes the keys and certificates in `dir` (all but the bundle).
pub fn make(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(dir.join("probe-ca.cnf"), SETTINGS).map_err(|e| format!("settings: {e}"))?;
    for name in ["ca", "nginx", "host-a", "host-b"] {
        let key = format!("{name}.key");
        openssl(
            dir,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                &key,
            ],
        )?;
    }
    let self_signed = |name: &str, subject: &str, section: &str| {
        openssl(
            dir,
            &[
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                DAYS,
                "-key",
                &format!("{name}.key"),
                "-subj",
                subject,
                "-config",
                "probe-ca.cnf",
                "-extensions",
                section,
                "-out",
                &format!("{name}.crt"),
            ],
        )
    };
    self_signed("ca", "/CN=stafeto probe CA", "ca")?;
    self_signed("host-b", "/CN=10.0.2.2", "host_b")?;
    for (name, subject, section, serial) in [
        ("nginx", "/CN=nginx.stafeto.test", "nginx", "2"),
        ("host-a", "/CN=host.stafeto.test", "host_a", "3"),
    ] {
        let request = format!("{name}.csr");
        openssl(
            dir,
            &[
                "req",
                "-new",
                "-key",
                &format!("{name}.key"),
                "-subj",
                subject,
                "-config",
                "probe-ca.cnf",
                "-out",
                &request,
            ],
        )?;
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-sha256",
                "-days",
                DAYS,
                "-in",
                &request,
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-set_serial",
                serial,
                "-extfile",
                "probe-ca.cnf",
                "-extensions",
                section,
                "-out",
                &format!("{name}.crt"),
            ],
        )?;
        let _ = std::fs::remove_file(dir.join(request));
    }
    Ok(())
}

/// The directory made where a file is missing (or always with `renew`), and
/// the bundle of Mozilla's roots with the CA, from the bundle that
/// tools/build-ca-bundle.py fetched.
pub fn ensure(renew: bool) -> Result<PathBuf, String> {
    let dir = dir();
    if renew || FILES.iter().any(|f| !dir.join(f).exists()) {
        let _ = std::fs::remove_dir_all(&dir);
        make(&dir)?;
        let mut bundle = crate::net_tls::ca_bundle().to_vec();
        if bundle.is_empty() {
            return Err("the root certificates are missing: tools/build-ca-bundle.py".into());
        }
        let ca = std::fs::read(dir.join("ca.crt")).map_err(|e| format!("ca.crt: {e}"))?;
        bundle.extend_from_slice(b"\nstafeto probe CA\n================\n");
        bundle.extend_from_slice(&ca);
        std::fs::write(dir.join("bundle-with-ca.crt"), bundle)
            .map_err(|e| format!("bundle-with-ca.crt: {e}"))?;
        println!("probe-ca: made {}", dir.display());
    }
    Ok(dir)
}

/// The bytes of `bundle-with-ca.crt`; empty while the CA has not been made
/// (the check of the descriptions needs the paths of an image only, and the
/// build of an image refuses an empty CA file).
pub fn bundle_with_ca() -> &'static [u8] {
    static BUNDLE: std::sync::Mutex<Option<&'static [u8]>> = std::sync::Mutex::new(None);
    crate::net_tls::file_once_made(&BUNDLE, &dir().join("bundle-with-ca.crt"))
}

/// The bytes of `nginx.crt` and `nginx.key`, the certificate and the key of
/// nginx in the images of `nginx-probe`; empty while the CA has not been
/// made (the build of such an image refuses them so).
pub fn nginx_certificate() -> &'static [u8] {
    static FILE: std::sync::Mutex<Option<&'static [u8]>> = std::sync::Mutex::new(None);
    crate::net_tls::file_once_made(&FILE, &dir().join("nginx.crt"))
}

pub fn nginx_key() -> &'static [u8] {
    static FILE: std::sync::Mutex<Option<&'static [u8]>> = std::sync::Mutex::new(None);
    crate::net_tls::file_once_made(&FILE, &dir().join("nginx.key"))
}

/// `cargo xtask probe-ca [--renew]`.
pub fn command(args: &[String]) -> Result<(), String> {
    let renew = match args {
        [] => false,
        [flag] if flag == "--renew" => true,
        _ => return Err("usage: cargo xtask probe-ca [--renew]".into()),
    };
    crate::net_build()?;
    let dir = ensure(renew)?;
    println!("probe-ca: {}", dir.display());
    Ok(())
}

/// Seconds since the epoch on the host.
fn host_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

/// The seconds the guest's clock, which printed `printed` (`date +%s`), is
/// off the host's; an error when it is too far for a check of certificates.
pub fn clock_verdict(printed: &[String]) -> Result<i64, String> {
    let guest: i64 = printed
        .iter()
        .find_map(|l| l.trim().parse().ok())
        .ok_or_else(|| format!("clock: no number in {printed:?}"))?;
    let off = guest - host_now();
    if off.abs() > CLOCK_SLACK_S {
        return Err(format!("clock: guest is off by {off} s"));
    }
    Ok(off)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(dir: &Path, file: &str) -> String {
        let out = Command::new("openssl")
            .current_dir(dir)
            .args(["x509", "-noout", "-subject", "-text", "-in", file])
            .output()
            .unwrap();
        assert!(out.status.success(), "{file}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn verifies(dir: &Path, file: &str) -> bool {
        Command::new("openssl")
            .current_dir(dir)
            .args(["verify", "-CAfile", "ca.crt", file])
            .output()
            .unwrap()
            .status
            .success()
    }

    /// The certificates carry the names of their servers, and the CA signs
    /// those it should.
    #[test]
    fn probe_ca_names_and_signatures() {
        let dir = std::env::temp_dir().join(format!("stafeto-probe-ca-{}", std::process::id()));
        make(&dir).unwrap();
        let ca = text(&dir, "ca.crt");
        assert!(
            ca.contains("stafeto probe CA") && ca.contains("CA:TRUE"),
            "{ca}"
        );
        let a = text(&dir, "host-a.crt");
        assert!(a.contains("DNS:host.stafeto.test"), "{a}");
        assert!(a.contains("IP Address:10.0.2.2"), "{a}");
        let n = text(&dir, "nginx.crt");
        assert!(n.contains("DNS:nginx.stafeto.test") && n.contains("IP Address:127.0.0.1"));
        let b = text(&dir, "host-b.crt");
        assert!(
            b.contains("IP Address:10.0.2.2") && !b.contains("DNS:"),
            "{b}"
        );
        assert!(verifies(&dir, "host-a.crt"));
        assert!(verifies(&dir, "nginx.crt"));
        assert!(!verifies(&dir, "host-b.crt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn probe_ca_clock_of_the_guest() {
        let now = host_now();
        assert!(clock_verdict(&[format!("{now}")]).is_ok());
        let off = clock_verdict(&[format!("{}", now - 3600)]).unwrap_err();
        assert!(off.starts_with("clock: guest is off by -3"), "{off}");
        assert!(clock_verdict(&["date: bad".to_owned()]).is_err());
    }
}
