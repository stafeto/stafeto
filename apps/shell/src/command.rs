// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The commands of the shell (spec 13.6): a line is words split on
//! spaces, and its first word names the command. `echo` takes the words
//! after it; `crash` takes `uart` alone; the other commands take no words
//! and leave those after them. A line of no words is no command; any other
//! line names no known command, and the shell says so.

/// A command, as a line names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// A line of no words.
    Empty,
    Help,
    /// The words after `echo`.
    Echo(Words<'a>),
    Uptime,
    Ps,
    Mem,
    Bench,
    CrashUart,
    /// The line, without the spaces around it.
    Unknown(&'a [u8]),
}

/// The words of a line: the runs of bytes between spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words<'a>(&'a [u8]);

impl<'a> Words<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.0.split(|&b| b == b' ').filter(|w| !w.is_empty())
    }
}

/// The lines of `help`: each command and what it does.
pub const HELP: [&str; 7] = [
    "help        list the commands",
    "echo WORDS  print the words",
    "uptime      the time since boot",
    "ps          the services and their state",
    "mem         the memory of each process",
    "bench       the round trip of a request and the latencies",
    "crash uart  crash the UART driver; init restarts it",
];

/// The command `line` names (the rules above).
pub fn parse(line: &[u8]) -> Command<'_> {
    let line = trimmed(line);
    if line.is_empty() {
        return Command::Empty;
    }
    let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    let (first, rest) = line.split_at(end);
    let rest = Words(rest);
    match first {
        b"help" => Command::Help,
        b"echo" => Command::Echo(rest),
        b"uptime" => Command::Uptime,
        b"ps" => Command::Ps,
        b"mem" => Command::Mem,
        b"bench" => Command::Bench,
        b"crash" if rest.iter().eq([&b"uart"[..]]) => Command::CrashUart,
        _ => Command::Unknown(line),
    }
}

/// `line` without the spaces at its start and end.
fn trimmed(line: &[u8]) -> &[u8] {
    let start = line.iter().position(|&b| b != b' ').unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(start, |i| i + 1);
    &line[start..end]
}

/// The line of the shell for a line that named no command, in its pieces:
/// `shell: unknown command: <line>; type help for the commands`.
pub fn unknown(line: &[u8]) -> [&[u8]; 3] {
    [
        b"shell: unknown command: ",
        line,
        b"; type help for the commands\n",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(c: Command<'_>) -> Vec<&[u8]> {
        match c {
            Command::Echo(w) => w.iter().collect(),
            other => panic!("{other:?} is no echo"),
        }
    }

    #[test]
    fn commands_split_on_spaces() {
        let hello: Vec<&[u8]> = vec![b"hello", b"stafeto"];
        assert_eq!(words(parse(b"echo hello stafeto")), hello);
        assert_eq!(words(parse(b"  echo   hello  stafeto ")), hello);
        assert_eq!(words(parse(b"echo")), Vec::<&[u8]>::new());
        for (line, command) in [
            (&b"help"[..], Command::Help),
            (b" uptime ", Command::Uptime),
            (b"ps", Command::Ps),
            (b"mem", Command::Mem),
            (b"bench", Command::Bench),
            (b"crash uart", Command::CrashUart),
            (b"crash   uart  ", Command::CrashUart),
            (b"", Command::Empty),
            (b"    ", Command::Empty),
        ] {
            assert_eq!(parse(line), command, "{:?}", String::from_utf8_lossy(line));
        }
        // A word glued to another is another word.
        assert_eq!(parse(b"echohello"), Command::Unknown(b"echohello"));
    }

    #[test]
    fn unknown_commands_are_named() {
        for (line, named) in [
            (&b"reboot"[..], &b"reboot"[..]),
            (b"  make  coffee ", b"make  coffee"),
            (b"crash", b"crash"),
            (b"crash init", b"crash init"),
            (b"crash uart now", b"crash uart now"),
        ] {
            assert_eq!(parse(line), Command::Unknown(named));
        }
        assert_eq!(
            unknown(b"reboot").concat(),
            b"shell: unknown command: reboot; type help for the commands\n"
        );
    }
}
