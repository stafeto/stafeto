#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# The input check of .github/workflows/probe.yml. The workflow hands the free
# text of its inputs over in the environment: PROBE_COMMAND (the words after
# `cargo xtask`), PROBE_ENV (words NAME=value), PROBE_REPEAT (1 to 10) and
# PROBE_TIMEOUT (minutes, 1 to 60). The script exits 0 when all four are fine
# and 1, with one line on stderr, at the first that is not. The tests are in
# tools/test_probe_validate.sh.

set -u

# Letters, digits, space and - _ . , = / : and nothing else. Bash anchors a
# regular expression to the whole string, so a newline is outside the set.
words='^[A-Za-z0-9 _.,=/:-]+$'

fail() {
    echo "probe: $1" >&2
    exit 1
}

command_line=${PROBE_COMMAND-}
env_line=${PROBE_ENV-}
repeat=${PROBE_REPEAT-}
timeout_minutes=${PROBE_TIMEOUT-}

[[ $command_line =~ $words ]] || fail "command is empty or has a character outside letters, digits, space and - _ . , = / :"
read -r -a command_words <<<"$command_line"
[[ ${command_words[0]} =~ ^[a-z][a-z0-9-]*$ ]] || fail "the first word of command must be an xtask command name"

if [ -n "$env_line" ]; then
    [[ $env_line =~ $words ]] || fail "env has a character outside letters, digits, space and - _ . , = / :"
    read -r -a env_words <<<"$env_line"
    for word in "${env_words[@]}"; do
        [[ $word =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || fail "env word '$word' is not NAME=value"
        name=${word%%=*}
        case $name in
        PATH | HOME | SHELL | BASH_ENV | ENV | LD_* | DYLD_* | GITHUB_* | RUNNER_* | CARGO_HOME | RUSTUP_HOME | RUSTUP_TOOLCHAIN | RUSTC* | RUSTFLAGS)
            fail "env may not set $name" ;;
        esac
    done
fi

[[ $repeat =~ ^[0-9]+$ ]] && [ "$repeat" -ge 1 ] && [ "$repeat" -le 10 ] || fail "repeat must be 1 to 10"
[[ $timeout_minutes =~ ^[0-9]+$ ]] && [ "$timeout_minutes" -ge 1 ] && [ "$timeout_minutes" -le 60 ] || fail "timeout must be 1 to 60 minutes"
exit 0
