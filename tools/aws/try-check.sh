#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin
#
# The check of the try-out image on a t4g.small (part A5; the instance is launched by the owner's
# session, the steps use the repository's own commands). It supersedes the steps 4 and 5 of
# switch-check.sh: the image now has nginx-fast and nginx in it.
#
# What a pass proves: the services of the try-out start on the ENA of a t4g.small, with the
# SSH host key made on the instance, the certificate made on the instance, the page written at
# boot, nginx on 80 and 443 over the sockets of the network service, and nginx-fast on 8080
# through the switch.
#
#   0. A fresh worktree needs its dependencies built once, before step 1 (without them
#      `cargo xtask aws image` stops with "build its package first"):
#        cargo xtask relibc
#        tools/build-busybox.py
#        tools/build-dropbear.py
#        tools/build-openssl.py
#        tools/build-curl.py
#        tools/build-nginx.py
#        tools/build-fstack.py
#      (one run each; about four minutes in all).
#   1. Build and register the image (nginx, nginx-fast, Dropbear, pkg and the page are in it):
#        cargo xtask aws image --session S
#      The image check of the plan's security floor has run before on the lists of the image
#      (`cargo xtask net-try` repeats it and runs the image on QEMU): nothing in /etc/dropbear,
#      every account locked with !, no private key in any file, only ports 22, 80, 443 and 8080.
#   2. Launch it with a key pair of the session, a security group open to this host's address
#      alone on 22, 80, 443 and 8080, and read the console:
#        cargo xtask aws boot --try --ami AMI --end "fast: nginx-fast on 8080" --serial 180 --session S
#      `--try` makes the key pair (kept in the session's directory, imported under the session's
#      tags), the group open to this host's public address alone (a /32 found with checkip) on
#      TCP 22, 80, 443 and 8080, and gives the instance a public address, written to the file
#      `address` of the session's directory (target/aws/S) and printed redacted. The instance
#      stays up after the command; `clean` removes it, the group and the key pair.
#      Lines that must appear (the order of the last four may vary: each runs in a subshell):
#        net: ena mac 02:..., link unknown     (EC2 sends no link event; `link up` or `unknown` both pass)
#        ena: link up                          (a line of its own, shortly after)
#        entropy: seeded from the boot page (64 bytes)
#        ec2-key: ...                          (the type and comment of the key pair)
#        ssh: host key SHA256:...              (the fingerprint of the host key of this boot)
#        dropbear: dropbear -F -s -j -k -r /etc/dropbear/dropbear_ed25519_host_key
#        landing: page written for ADDRESS (t4g.small)
#        web: certificate sha256 Fingerprint=...
#        web: nginx on 80 and 443
#        fast: nginx-fast on 8080
#      Lines that must not appear:
#        web: no certificate could be made, 443 stays off
#        fast: no nginx-fast in this image, 8080 stays off
#        fast: netd.conf has no switch, 8080 stays off
#        dropbear: no /root/.ssh/authorized_keys, SSH stays off
#        net: the ENA kind has no consumers of the switch yet
#        ena: reset reason
#   3. From the owner's machine (ADDRESS is the public address of the instance):
#        curl http://ADDRESS/                  the page, 200
#        curl -k https://ADDRESS/              the same page over TLS 1.3 (the certificate is self-signed)
#        curl http://ADDRESS:8080/             the same page from nginx-fast
#        ssh -i target/aws/S/try-key root@ADDRESS
#                                              the key pair of the instance gets in; the fingerprint of
#                                              the host key is the one of the console line
#        nmap -Pn -p 1-65535 ADDRESS           a full TCP scan: only 22, 80, 443 and 8080 are open
#        nmap -Pn -sU --top-ports 200 ADDRESS  UDP: nothing answers but what the security group
#                                              lets through (the group of the instance opens the four
#                                              TCP ports to the operator's address alone)
#      Run both from the operator's host, outside the VPC, on the public address.
#      The page says what stafeto is, that it is experimental, how to log in, what to try, that
#      files and packages are gone after a reboot, that the host key changes at every boot, and
#      the warning about secrets and the security group.
#   4. In the session on the instance:
#        posix-net stat                        (a test program of tests/posix-so: the image has no
#                                              /bin/posix-net, so this line runs only where it is
#                                              added) `consumers` equal to the workers of nginx-fast (2),
#                                              `rx_consumer` and `tx_consumer` above 0 after the
#                                              curl of 8080, `tx_refused 0`, `rx_full 0`
#        date -u -s "YYYY-MM-DD HH:MM:SS"      first: the clock starts at 2026-01-01 and `pkg` refuses the
#                                              certificate of stafeto.github.io until it is set
#        pkg update; pkg search nginx          the index of the series 0.5 from stafeto.github.io
#        pkg install htop; TERM=vt100 htop     a package from the store in memory (the image has no
#                                              terminfo for xterm)
#        ps; cat /proc/meminfo                 nginx, nginx-fast and dropbear are running; the
#                                              memory fits the 2 GiB (the console line `frames N
#                                              MiB free` before the services shows what there is;
#                                              the full image prints no `init: free pages` line)
#   5. Ten minutes of curl in a loop against 80, 443 and 8080: no `ena: reset` line, the
#      keep-alive counters go on (`ena: keepalive N`).
#
# End of the session: `cargo xtask aws clean --session S` terminates the instance and removes the group and the key pair.
echo "see the comments of this file: the steps and the expected console lines"
