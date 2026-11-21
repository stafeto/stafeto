// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

use super::*;

const IMAGE: Files<'static> = Files {
    passwd: b"root:x:0:0:root:/root:/bin/ash\nuser:x:1000:100:user:/home/user:/bin/ash\nnobody:x:65534:65534:nobody:/:/bin/ash\n",
    group: b"root:x:0:root\nwheel:x:10:user\nuser:x:100:user\nnobody:x:65534:nobody\n",
    shadow: b"root:!:20000:0:99999:7:::\nuser:!:20000:0:99999:7:::\nnobody:!:20000:0:99999:7:::\n",
};

/// What the merge gave and what it refused.
struct Run {
    out: Merged,
    notes: [(&'static str, [u8; 32], usize, Reason); 16],
    count: usize,
}

impl Run {
    fn passwd(&self) -> &str {
        core::str::from_utf8(self.out.passwd.data()).unwrap()
    }
    fn group(&self) -> &str {
        core::str::from_utf8(self.out.group.data()).unwrap()
    }
    fn shadow(&self) -> &str {
        core::str::from_utf8(self.out.shadow.data()).unwrap()
    }
    /// The notes as `file:name:reason`.
    fn refused(&self) -> std::vec::Vec<std::string::String> {
        self.notes[..self.count]
            .iter()
            .map(|(file, name, len, reason)| {
                std::format!(
                    "{file}:{}:{reason:?}",
                    core::str::from_utf8(&name[..*len]).unwrap()
                )
            })
            .collect()
    }
}

fn run(volume: &Files<'_>, options: &Options<'_>) -> Run {
    let mut run = Run {
        out: Merged::new(),
        notes: [("", [0; 32], 0, Reason::Malformed); 16],
        count: 0,
    };
    let (out, notes, count) = (&mut run.out, &mut run.notes, &mut run.count);
    merge(&IMAGE, volume, options, out, &mut |n: Note<'_>| {
        if *count < 16 {
            let mut name = [0u8; 32];
            let len = n.name.len().min(32);
            name[..len].copy_from_slice(&n.name[..len]);
            notes[*count] = (n.file, name, len, n.reason);
            *count += 1;
        }
    });
    run
}

fn same_as_image(r: &Run) {
    assert_eq!(r.passwd().as_bytes(), IMAGE.passwd);
    assert_eq!(r.group().as_bytes(), IMAGE.group);
    assert_eq!(r.shadow().as_bytes(), IMAGE.shadow);
}

#[test]
fn an_empty_volume_gives_the_image() {
    let r = run(&Files::default(), &Options::default());
    same_as_image(&r);
    assert!(r.refused().is_empty());
}

#[test]
fn the_image_comes_back_with_every_file_of_the_volume_missing_or_partial() {
    // The shadow file alone (a cut between the writes): the accounts are the image's.
    let volume = Files {
        shadow: b"root:$6$salt$hash:19000:0:99999:7:::\n",
        ..Files::default()
    };
    let r = run(&volume, &Options::default());
    assert_eq!(r.passwd().as_bytes(), IMAGE.passwd);
    assert_eq!(r.group().as_bytes(), IMAGE.group);
    assert!(
        r.shadow()
            .starts_with("root:$6$salt$hash:19000:0:99999:7:::\n")
    );
    assert!(r.shadow().contains("user:!:20000:0:99999:7:::\n"));
}

#[test]
fn a_password_of_an_image_account_and_the_members_of_an_image_group_come_from_the_volume() {
    let volume = Files {
        passwd: IMAGE.passwd,
        group: b"root:x:0:root\nwheel:x:10:user,bob\nuser:x:100:user\nnobody:x:65534:nobody\n",
        shadow: b"root:$6$a$b:19000:0:99999:7:::\nuser:!:20000:0:99999:7:::\nnobody:!:20000:0:99999:7:::\n",
    };
    let r = run(&volume, &Options::default());
    assert!(r.group().contains("wheel:x:10:user,bob\n"));
    assert!(r.shadow().contains("root:$6$a$b:19000:0:99999:7:::\n"));
    assert!(r.refused().is_empty());
}

#[test]
fn an_account_of_the_volume_is_accepted_with_its_group_and_a_locked_shadow_when_it_has_none() {
    let volume = Files {
        passwd: b"bob:x:1001:1001:Bob:/data/home/bob:/bin/ash\n",
        group: b"bob:x:1001:\n",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert!(
        r.passwd()
            .ends_with("bob:x:1001:1001:Bob:/data/home/bob:/bin/ash\n")
    );
    assert!(r.group().ends_with("bob:x:1001:\n"));
    assert!(r.shadow().ends_with("bob:!:20000:0:99999:7:::\n"));
    assert!(r.refused().is_empty());
}

#[test]
fn an_account_whose_numbers_or_group_are_wrong_is_refused_by_name() {
    let volume = Files {
        passwd: b"low:x:500:100:low:/:/bin/ash\n\
                  edge:x:65534:100:edge:/:/bin/ash\n\
                  clash:x:1000:100:clash:/:/bin/ash\n\
                  root2:x:0:0:root2:/:/bin/ash\n\
                  nogroup:x:1500:1500:nogroup:/:/bin/ash\n\
                  fine:x:1002:100:fine:/data/home/fine:/bin/ash\n",
        group: b"",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert_eq!(
        r.refused(),
        [
            "passwd:low:UidRange",
            "passwd:edge:UidRange",
            "passwd:clash:NumberTaken",
            "passwd:root2:UidRange",
            "passwd:nogroup:NoGroup",
        ]
    );
    assert!(r.passwd().contains("fine:x:1002:100:"));
    assert!(!r.passwd().contains("root2"));
}

#[test]
fn an_entry_of_uid_0_under_another_name_is_never_accepted_and_the_image_root_is_untouched() {
    let volume = Files {
        passwd: b"toor:x:0:0:toor:/root:/bin/ash\nroot:x:0:0:evil:/tmp:/bin/sh\n",
        group: b"",
        shadow: b"toor:$6$a$b:1:0:99999:7:::\n",
    };
    let r = run(&volume, &Options::default());
    assert!(!r.passwd().contains("toor"));
    assert!(!r.shadow().contains("toor"));
    // The image's line of root (its home and shell too) is what is given.
    assert!(r.passwd().starts_with("root:x:0:0:root:/root:/bin/ash\n"));
}

#[test]
fn a_volume_cannot_change_the_numbers_or_the_name_of_an_image_account() {
    let volume = Files {
        passwd: b"user:x:0:0:user:/root:/bin/ash\nnobody:x:1:1:nobody:/:/bin/ash\n",
        group: b"wheel:x:0:user\nuser:x:0:user\n",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert!(
        r.passwd()
            .contains("user:x:1000:100:user:/home/user:/bin/ash\n")
    );
    assert!(r.passwd().contains("nobody:x:65534:65534:"));
    assert!(r.group().contains("wheel:x:10:user\n"));
    assert!(r.group().contains("user:x:100:user\n"));
}

#[test]
fn a_group_of_the_volume_needs_a_number_of_1000_or_more_that_nobody_has() {
    let volume = Files {
        passwd: b"",
        group: b"low:x:50:\nops:x:1000:\nops2:x:1000:\nweird:x:65534:\n",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert_eq!(
        r.refused(),
        [
            "group:low:GidRange",
            "group:ops2:NumberTaken",
            "group:weird:GidRange"
        ]
    );
    assert!(r.group().contains("ops:x:1000:\n"));
}

#[test]
fn an_account_of_the_image_that_the_volume_lacks_is_added_locked_and_a_hash_of_none_is_a_lock() {
    // The volume has an old set: no `nobody`, no `user`; an empty hash of root.
    let volume = Files {
        passwd: b"root:x:0:0:root:/root:/bin/ash\n",
        group: b"root:x:0:root\n",
        shadow: b"root::19000:0:99999:7:::\n",
    };
    let r = run(&volume, &Options::default());
    assert_eq!(r.passwd().as_bytes(), IMAGE.passwd);
    assert!(r.shadow().starts_with("root:!:19000:0:99999:7:::\n"));
    assert!(r.shadow().contains("user:!:20000:0:99999:7:::\n"));
}

#[test]
fn lines_that_are_not_well_formed_are_dropped_with_a_note() {
    let volume = Files {
        passwd: b"a:x:1010:100:a:/:/bin/ash:extra\n\
                  Bad:x:1011:100:a:/:/bin/ash\n\
                  c:x:abc:100:c:/:/bin/ash\n\
                  d:y:1012:100:d:/:/bin/ash\n\
                  e:x:1013:100:e:rel:/bin/ash\n\
                  ok:x:1014:100:ok:/:/bin/ash\n",
        group: b"",
        shadow: b"ok:$6$x$y:1:2:3:4:5:6\nok:$6$x$y:1:2:3:4:5:6:7:8\n",
    };
    let r = run(&volume, &Options::default());
    assert_eq!(r.refused().len(), 5);
    assert!(r.refused().iter().all(|n| n.ends_with("Malformed")));
    assert!(r.passwd().contains("ok:x:1014:100:"));
    // Both shadow lines of `ok` are malformed: the account is locked.
    assert!(r.shadow().contains("ok:!:20000:0:99999:7:::\n"));
}

#[test]
fn the_name_rule_holds() {
    assert!(valid_name(b"bob"));
    assert!(valid_name(b"_svc-1"));
    assert!(!valid_name(b""));
    assert!(!valid_name(b"1bob"));
    assert!(!valid_name(b"Bob"));
    assert!(!valid_name(b"bo b"));
    assert!(!valid_name(b"bo:b"));
    assert!(!valid_name(&[b'a'; 33]));
    assert!(valid_name(&[b'a'; 32]));
}

#[test]
fn the_home_of_an_image_account_is_the_one_the_caller_names() {
    let options = Options {
        home: Some((b"user", b"/data/home/user")),
    };
    let r = run(&Files::default(), &options);
    assert!(
        r.passwd()
            .contains("user:x:1000:100:user:/data/home/user:/bin/ash\n")
    );
    assert!(r.passwd().contains("root:x:0:0:root:/root:/bin/ash\n"));
}

#[test]
fn a_member_that_is_not_a_name_is_dropped_from_a_list() {
    let volume = Files {
        passwd: b"",
        group: b"wheel:x:10:user,Bad Name,bob,\n",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert!(r.group().contains("wheel:x:10:user,bob\n"));
}

#[test]
fn a_full_result_leaves_accounts_out_and_says_so() {
    let mut text = std::string::String::new();
    for i in 0..60 {
        text.push_str(&std::format!(
            "u{i}:x:{}:100:{}:/:/bin/ash\n",
            2000 + i,
            "g".repeat(200)
        ));
    }
    let volume = Files {
        passwd: text.as_bytes(),
        group: b"",
        shadow: b"",
    };
    let r = run(&volume, &Options::default());
    assert!(r.out.passwd.full);
    assert!(r.refused().iter().any(|n| n.ends_with("Full")));
    // The files stay whole lines.
    assert!(r.passwd().ends_with('\n'));
}
