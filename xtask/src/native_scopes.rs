// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Both pthread images and the genuine loader child are mandatory.

#[path = "../../tests/posix-threads/src/native_mode.rs"]
mod observation;

pub fn both_images(
    vz: bool,
    stock: fn(bool) -> Result<(), String>,
    native: fn(bool) -> Result<(), String>,
) -> Result<(), String> {
    stock(vz)?;
    native(vz)
}

/// The probe build says "router ended without handoff" when it repairs a
/// router that ended past `rt`; each image has exactly one such thread
/// by design (the thread that ends past the library in the pthread image,
/// variant R5 in the native one). More lines would hide a handoff that
/// another path lost.
pub fn check_ended_routers(lines: &[String], expected: usize) -> Result<(), String> {
    let found = lines
        .iter()
        .filter(|line| line.trim() == "router ended without handoff")
        .count();
    if found == expected {
        Ok(())
    } else {
        Err(format!(
            "{found} lines \"router ended without handoff\", expected {expected}"
        ))
    }
}

pub fn check_markers(lines: &[String]) -> Result<(), String> {
    let selected = |prefix: &str| -> Result<u32, String> {
        let mut values = lines
            .iter()
            .filter_map(|line| line.trim().strip_prefix(prefix));
        let value = values.next().ok_or_else(|| format!("missing {prefix}"))?;
        if values.next().is_some() {
            return Err(format!("repeated {prefix}"));
        }
        observation::parent_pid(value.as_bytes()).ok_or_else(|| format!("invalid {prefix}"))
    };
    let child_parent = selected("native-scopes: loader-ready parent=")?;
    let supervisor = selected("native-scopes-supervisor: ok parent=")?;
    if child_parent <= 1 || child_parent != supervisor {
        return Err("native child and genuine supervisor parent differ".into());
    }
    if lines
        .iter()
        .filter(|line| line.trim() == "native-scopes: survivor and join ok")
        .count()
        != 1
    {
        return Err("native survivor and join marker missing or repeated".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    static CALLS: std::sync::Mutex<Vec<bool>> = std::sync::Mutex::new(Vec::new());
    fn stock(vz: bool) -> Result<(), String> {
        CALLS.lock().unwrap().push(vz);
        Ok(())
    }
    fn refused(_: bool) -> Result<(), String> {
        Err("native child failed".into())
    }
    #[test]
    fn native_refusal_fails_the_complete_thread_command() {
        CALLS.lock().unwrap().clear();
        assert!(both_images(true, stock, refused).is_err());
        assert_eq!(*CALLS.lock().unwrap(), vec![true]);
    }
    #[test]
    fn markers_require_a_real_child_and_matching_supervisor() {
        let valid = vec![
            "native-scopes: loader-ready parent=256".into(),
            "native-scopes: survivor and join ok".into(),
            "native-scopes-supervisor: ok parent=256".into(),
        ];
        assert!(check_markers(&valid).is_ok());
        for removed in 0..3 {
            let mut missing = valid.clone();
            missing.remove(removed);
            assert!(check_markers(&missing).is_err());
        }
        let mut wrong = valid.clone();
        wrong[2] = "native-scopes-supervisor: ok parent=257".into();
        assert!(check_markers(&wrong).is_err());
        wrong[2] = "native-scopes-supervisor: ok parent=4294967296".into();
        assert!(check_markers(&wrong).is_err());
    }
    #[test]
    fn repaired_routers_are_counted() {
        let line = || "router ended without handoff".to_string();
        assert!(check_ended_routers(&[line()], 1).is_ok());
        assert!(check_ended_routers(&[], 1).is_err());
        assert!(check_ended_routers(&[line(), line()], 1).is_err());
    }
    #[test]
    fn parent_observation_is_strict_and_bounded() {
        assert_eq!(observation::parent_pid(b"4294967295"), Some(u32::MAX));
        assert_eq!(observation::ARGUMENT, b"native-scope-only");
        for invalid in [
            b"".as_slice(),
            b"0",
            b"-1",
            b"+1",
            b" 1",
            b"1\n",
            b"4294967296",
        ] {
            assert_eq!(observation::parent_pid(invalid), None);
        }
    }
}
