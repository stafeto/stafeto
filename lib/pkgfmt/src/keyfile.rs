// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The key files. A public key is one line, `ed25519 <base64 of 32 bytes>
//! <name>` and a newline, in a file `<name>.pub`. A private key is an
//! unencrypted PKCS#8 version 1 Ed25519 key in PEM (the shape
//! `openssl genpkey -algorithm ed25519` writes): 48 bytes of DER that start
//! with a fixed 16-byte prefix and end with the 32-byte seed.

use crate::trust::Key;
use crate::{Error, Name, b64};

/// The DER bytes before the seed of a PKCS#8 version 1 Ed25519 key.
pub const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const BEGIN: &str = "-----BEGIN PRIVATE KEY-----\n";
const END: &str = "-----END PRIVATE KEY-----\n";

/// The key of a `.pub` file's content.
pub fn parse_public(text: &str) -> Result<Key, Error> {
    let line = text.strip_suffix('\n').ok_or(Error::BadKeyFile)?;
    let mut words = line.split(' ');
    let (Some("ed25519"), Some(b64text), Some(name), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return Err(Error::BadKeyFile);
    };
    let mut raw = [0u8; 33];
    if b64text.len() != 44 || b64::decode(b64text, &mut raw)? != 32 {
        return Err(Error::BadKeyFile);
    }
    Ok(Key {
        name: Name::new(name).map_err(|_| Error::BadKeyFile)?,
        public: raw[..32].try_into().expect("32 bytes"),
    })
}

/// The seed of an unencrypted PKCS#8 Ed25519 key in PEM.
pub fn parse_private(pem: &str) -> Result<[u8; 32], Error> {
    let body = pem
        .strip_prefix(BEGIN)
        .and_then(|p| p.strip_suffix(END))
        .ok_or(Error::NotPkcs8Ed25519)?;
    if !body.ends_with('\n') {
        return Err(Error::NotPkcs8Ed25519);
    }
    let mut joined = [0u8; 128];
    let mut n = 0;
    for &c in body.as_bytes() {
        if c == b'\n' {
            continue;
        }
        if n == joined.len() {
            return Err(Error::NotPkcs8Ed25519);
        }
        joined[n] = c;
        n += 1;
    }
    let text = core::str::from_utf8(&joined[..n]).map_err(|_| Error::NotPkcs8Ed25519)?;
    let mut der = [0u8; 96];
    if text.len() != 64 || b64::decode(text, &mut der).map_err(|_| Error::NotPkcs8Ed25519)? != 48 {
        return Err(Error::NotPkcs8Ed25519);
    }
    if der[..16] != PKCS8_PREFIX {
        return Err(Error::NotPkcs8Ed25519);
    }
    Ok(der[16..48].try_into().expect("32 bytes"))
}

/// The `.pub` line of a key.
#[cfg(any(test, feature = "write"))]
pub fn public_line(key: &Key) -> alloc::string::String {
    let mut buf = [0u8; 44];
    alloc::format!(
        "ed25519 {} {}\n",
        b64::encode(&key.public, &mut buf),
        key.name.as_str()
    )
}

/// The PEM text of a seed.
#[cfg(any(test, feature = "write"))]
pub fn private_pem(seed: &[u8; 32]) -> alloc::string::String {
    let mut der = [0u8; 48];
    der[..16].copy_from_slice(&PKCS8_PREFIX);
    der[16..].copy_from_slice(seed);
    let mut buf = [0u8; 64];
    alloc::format!("{BEGIN}{}\n{END}", b64::encode(&der, &mut buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8410, section 10.3: the private key and its public half.
    const RFC8410_PEM: &str =
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
    const RFC8410_PUBLIC: &str = "Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

    #[test]
    fn the_rfc_8410_key_gives_its_public_half() {
        let seed = parse_private(RFC8410_PEM).unwrap();
        let mut buf = [0u8; 44];
        assert_eq!(b64::encode(&crate::sig::public_key(&seed), &mut buf), RFC8410_PUBLIC);
        assert_eq!(private_pem(&seed), RFC8410_PEM);
    }

    #[test]
    fn other_private_shapes_are_refused() {
        for bad in [
            "",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            // A version 2 key carries the public half: 83 bytes of DER.
            "-----BEGIN PRIVATE KEY-----\nMHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PRIVATE KEY-----\n",
        ] {
            assert_eq!(parse_private(bad), Err(Error::NotPkcs8Ed25519));
        }
        let mut shifted = RFC8410_PEM.replace("MC4CAQAw", "MC4CAQEw");
        assert_eq!(parse_private(&shifted), Err(Error::NotPkcs8Ed25519));
        shifted = RFC8410_PEM.replace("\n-----END", "-----END");
        assert_eq!(parse_private(&shifted), Err(Error::NotPkcs8Ed25519));
    }

    #[test]
    fn public_lines_are_strict() {
        let k = parse_public("ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= t-root\n").unwrap();
        assert_eq!(k.name.as_str(), "t-root");
        assert_eq!(public_line(&k), "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= t-root\n");
        for bad in [
            "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= t-root",
            "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=  t-root\n",
            "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= t-root extra\n",
            "rsa Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= t-root\n",
            "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE t-root\n",
            "ed25519 Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE= T-root\n",
        ] {
            assert_eq!(parse_public(bad), Err(Error::BadKeyFile), "{bad:?}");
        }
    }
}
