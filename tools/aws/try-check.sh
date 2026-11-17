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
#   1. Build and register the image (nginx, nginx-fast, Dropbear, pkg and the page are in it):
#        cargo xtask aws image --session S
#      The image check of the plan's security floor has run before on the lists of the image
#      (`cargo xtask net-try` repeats it and runs the image on QEMU): nothing in /etc/dropbear,
#      every account locked with !, no private key in any file, only ports 22, 80, 443 and 8080.
#   2. Launch it with the key pair of the owner, a security group open to the owner's address
#      alone on 22, 80, 443 and 8080, and read the console:
#        cargo xtask aws boot --ami AMI --end "fast: nginx-fast on 8080" --serial 180 --session S
#      Lines that must appear (the order of the last four may vary: each runs in a subshell):
#        net: ena mac 02:..., link up
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
#        ssh root@ADDRESS                      the key pair of the instance gets in; the fingerprint of
#                                              the host key is the one of the console line
#        nc -z -w 2 ADDRESS PORT               refused (or filtered) for every other port
#      The page says what stafeto is, that it is experimental, how to log in, what to try, that
#      files and packages are gone after a reboot, that the host key changes at every boot, and
#      the warning about secrets and the security group.
#   4. In the session on the instance:
#        posix-net stat                        `consumers` equal to the workers of nginx-fast (2),
#                                              `rx_consumer` and `tx_consumer` above 0 after the
#                                              curl of 8080, `tx_refused 0`, `rx_full 0`
#        pkg update; pkg search nginx          the index of the series 0.5 from stafeto.github.io
#        pkg install htop; htop                a package from the store in memory
#        ps; cat /proc/meminfo                 nginx, nginx-fast and dropbear are running; the
#                                              memory the table holds fits the 2 GiB (the line
#                                              `init: free pages` of the console is 16 384 or more)
#   5. Ten minutes of curl in a loop against 80, 443 and 8080: no `ena: reset` line, the
#      keep-alive counters go on (`ena: keepalive N`).
#
# Stop the instance at the end: `cargo xtask aws clean --session S`.
echo "see the comments of this file: the steps and the expected console lines"
