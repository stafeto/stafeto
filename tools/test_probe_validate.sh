#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# Tests of tools/probe-validate.sh with good and hostile inputs:
# `bash tools/test_probe_validate.sh`.

set -u
here=$(cd "$(dirname "$0")" && pwd)
bad=0

# check EXPECT COMMAND ENV REPEAT TIMEOUT
check() {
    local expect=$1
    PROBE_COMMAND=$2 PROBE_ENV=$3 PROBE_REPEAT=$4 PROBE_TIMEOUT=$5 bash "$here/probe-validate.sh" 2>/dev/null
    local got=$?
    if { [ "$expect" = ok ] && [ $got -ne 0 ]; } || { [ "$expect" = reject ] && [ $got -eq 0 ]; }; then
        echo "FAILED: expected $expect: command=[$2] env=[$3] repeat=[$4] timeout=[$5]"
        bad=1
    fi
}

check ok "budget-breaks" "" 1 30
check ok "kernel-test 512M" "" 3 60
check ok "net-probe" "NET_PROBE_RUNS=r" 10 1
check ok "posix-net --path /a/b:c,d.e" "A=1 B_2=x/y" 2 30
check ok "ci --group net" "" 1 30

check reject "" "" 1 30
check reject "kernel-test; curl x" "" 1 30
check reject 'kernel-test $(id)' "" 1 30
check reject 'kernel-test `id`' "" 1 30
check reject "kernel-test | cat" "" 1 30
check reject "kernel-test && id" "" 1 30
check reject "kernel-test > /x" "" 1 30
check reject "kernel-test 'a'" "" 1 30
check reject 'kernel-test "a"' "" 1 30
check reject 'kernel-test \a' "" 1 30
check reject 'kernel-test $HOME' "" 1 30
check reject $'budget-breaks\nid' "" 1 30
check reject "--help" "" 1 30
check reject "Budget" "" 1 30
check reject "budget-breaks" 'A=$(id)' 1 30
check reject "budget-breaks" 'A=1; id' 1 30
check reject "budget-breaks" $'A=1\nB=2' 1 30
check reject "budget-breaks" "novalue" 1 30
check reject "budget-breaks" "=x" 1 30
check reject "budget-breaks" "PATH=/tmp" 1 30
check reject "budget-breaks" "LD_PRELOAD=/tmp/x.so" 1 30
check reject "budget-breaks" "BASH_ENV=/tmp/x" 1 30
check reject "budget-breaks" "GITHUB_ENV=/tmp/x" 1 30
check reject "budget-breaks" "" 0 30
check reject "budget-breaks" "" 11 30
check reject "budget-breaks" "" "1;id" 30
check reject "budget-breaks" "" "" 30
check reject "budget-breaks" "" 1 0
check reject "budget-breaks" "" 1 61
check reject "budget-breaks" "" 1 "a"

[ $bad -eq 0 ] && echo "probe-validate: all cases pass"
exit $bad
