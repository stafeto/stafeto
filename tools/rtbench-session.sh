#!/bin/sh
# One session of the S5 comparison (docs/non-preemptible-paths.md): the base
# and the head each run `cargo xtask rtbench --minutes 10 --serial`, in the
# order given, and the figures land in a directory that `cargo xtask
# rtbench-check` reads (`order`, `base/`, `head/`, rtbench-hvf.txt and
# rtbench-vz.txt). Before each run the script builds, and then waits until the one-minute load
# average of the host is under LOAD_MAX (4 by default) and writes the load it
# found to `load.log` in the session directory, so that a session started on
# a busy host shows it. It gives up on a busy host after WAIT_MAX_MINUTES
# (240 by default) and exits with 3 without starting the run.
#
# usage: tools/rtbench-session.sh SESSION_DIR base-first|head-first BASE_TREE HEAD_TREE
#
# BASE_TREE and HEAD_TREE are checkouts of the two commits. The script does not
# build or check anything else and starts no other process on the host.
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 SESSION_DIR base-first|head-first BASE_TREE HEAD_TREE" >&2
    exit 2
fi
session=$1
order=$2
base_tree=$3
head_tree=$4
case "$order" in
base-first | head-first) ;;
*)
    echo "$0: order must be base-first or head-first (got $order)" >&2
    exit 2
    ;;
esac

load_max=${LOAD_MAX:-4}
wait_max=${WAIT_MAX_MINUTES:-240}
mkdir -p "$session/base" "$session/head"
log="$session/load.log"
echo "$order" >"$session/order"

# The one-minute load average: "{ 2.10 3.00 3.10 }" on macOS, the first word of
# /proc/loadavg elsewhere.
load_now() {
    if [ -r /proc/loadavg ]; then
        cut -d' ' -f1 /proc/loadavg | tr ',' '.'
    else
        sysctl -n vm.loadavg | tr -d '{}' | tr ',' '.' | awk '{ print $1 }'
    fi
}

# Wait for a quiet host, log the load of each look, return 3 on a timeout.
wait_quiet() {
    what=$1
    waited=0
    while :; do
        now=$(load_now)
        echo "$(date '+%Y-%m-%d %H:%M:%S') $what load $now (limit $load_max, waited $waited min)" >>"$log"
        if awk -v now="$now" -v max="$load_max" 'BEGIN { exit !(now < max) }'; then
            return 0
        fi
        if [ "$waited" -ge "$wait_max" ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') $what gave up: the host stayed busy" >>"$log"
            return 3
        fi
        sleep 60
        waited=$((waited + 1))
    done
}

run_one() {
    which=$1
    tree=$2
    # The build raises the load of the host itself: it goes first (one short
    # round, which builds the images of the run), and the wait for a quiet
    # host comes after it.
    (cd "$tree" && cargo xtask rtbench --short >/dev/null 2>&1) || return 4
    wait_quiet "$which before" || return 3
    (cd "$tree" && cargo xtask rtbench --minutes 10 --serial)
    cp "$tree/target/measure/rtbench-hvf.txt" "$tree/target/measure/rtbench-vz.txt" "$session/$which/"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $which done, load $(load_now)" >>"$log"
}

if [ "$order" = base-first ]; then
    run_one base "$base_tree"
    run_one head "$head_tree"
else
    run_one head "$head_tree"
    run_one base "$base_tree"
fi
