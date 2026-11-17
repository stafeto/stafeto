#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin
#
# The one-hour check of the switch of the network service on the ENA of a t4g.small
# (part A4). The instance is launched by the owner's session; the steps below use the
# repository's own commands.
#
# What a pass proves. Part A5 put nginx-fast and nginx in `boot-aws.img`: steps 1 to 3 prove that
# netd starts with `switch 8` on the ENA and that the plain path (DHCP, ping, the sockets of the
# service) works with the switch tables in place, and steps 4 and 5 prove the consumer path.
# `try-check.sh` is the check of the whole try-out image, with the page and the SSH server.
#
#   1. Build and register the image (it has the switch since part A5):
#        cargo xtask aws image --session S
#      The image has `/etc/netd.conf` with `switch 8` and `flows 16384`.
#   2. Boot it and read the console:
#        cargo xtask aws boot --ami AMI --end "net: ena mac" --serial 120 --session S
#      Lines that must appear, in this order (numbers vary):
#        ena: link up
#        net: ena mac 02:..., link up
#        ena: first interrupt of vector 1
#      Lines that must not appear:
#        net: the ENA kind has no consumers of the switch yet
#        net: netd.conf line
#        ena: reset reason          (no reset in the hour)
#   3. From the shell on the EC2 serial console: `posix-net stat`. Expected: `consumers 0`,
#      `tx_refused 0`, `rx_full 0`; the address and ping of the gateway work as without the switch.
#   4. nginx-fast starts from /etc/rc.d/fast with `/etc/nginx/nginx-fast-try.conf` (port 8080, two
#      workers). Expected console line: `fast: nginx-fast on 8080`. `posix-net stat` then shows
#      `consumers` equal to the worker count. After `curl http://ADDRESS:8080/` from another host in the
#      security group: `rx_consumer` and `tx_consumer` above 0, `tx_refused 0`, `rx_full 0`.
#   5. Regular nginx on 80 (/etc/rc.d/web) through the sockets of the service still answers
#      (`curl http://ADDRESS/`): the stack and the consumers share the address.
#   6. Ten minutes of curl in a loop against 8080 (or 80 without the package): no `ena: reset`
#      line, the keep-alive counters go on (`ena: keepalive N`).
#
# Stop the instance at the end: `cargo xtask aws clean --session S`.
echo "see the comments of this file: the steps and the expected console lines"
