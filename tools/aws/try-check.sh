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
#      On macOS the C parts of littlefs are archived with the `llvm-ar` of the Rust toolchain (lib/datafs/build.rs,
#      component `llvm-tools`), so no `AR` is set; Apple's `ar` leaves ELF archives with no symbol index.
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
#        efi-loader: time N from GetTime       (the firmware's time, written into boot-time)
#        clock: ready (started at N from the boot image)   (N within seconds of the host's date +%s)
#        ec2-key: ...                          (the type and comment of the key pair)
#        nvme: Amazon Elastic Block Store fw ... sn ..., N blocks of 512 bytes ...
#                                              (the disk service of the data volume found the second NVMe
#                                              function, and EBS names it sdf; the record names the second
#                                              function of the measured walk order, and a root volume found
#                                              there is refused by the name check: `nvme: datadisk is not
#                                              the data volume, left alone`; the line ends with the
#                                              controller's mqes, to and dstrd)
#        datafs: partition table written, data volume formatted, ...
#                                              (the first boot of a volume) or
#        datafs: data volume mounted, ...      (a later boot: mounted, never formatted again)
#        datakey: no host key on /data, ...    (first boot) then datakey: host key saved to /data
#        datakey: host key restored from /data (every later boot of the same volume)
#        ssh: host key SHA256:...              (the fingerprint of the host key; the same on every boot of
#                                              an instance with the data volume)
#        dropbear: dropbear -F -s -j -k -r /etc/dropbear/dropbear_ed25519_host_key
#        landing: page written for ADDRESS (t4g.small)
#        web: certificate sha256 Fingerprint=...
#        web: nginx on 80 and 443
#        fast: nginx-fast on 8080
#      Lines that must not appear with the data volume:
#        init: left out: datadisk
#        nvme: datadisk is not the data volume, left alone
#        datafs: no disk: ...
#      Lines that must not appear:
#        web: no certificate could be made, 443 stays off
#        fast: no nginx-fast in this image, 8080 stays off
#        fast: netd.conf has no switch, 8080 stays off
#        dropbear: no authorized_keys of user, SSH stays off
#        net: the ENA kind has no consumers of the switch yet
#        ena: reset reason
#   3. From the owner's machine (ADDRESS is the public address of the instance):
#        curl http://ADDRESS/                  the page, 200
#        curl -k https://ADDRESS/              the same page over TLS 1.3 (the certificate is self-signed)
#        curl http://ADDRESS:8080/             the same page from nginx-fast
#        ssh -i target/aws/S/try-key user@ADDRESS
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
#        date -u                               within a few seconds of the host's `date -u` (before pkg update)
#        date -u -s "YYYY-MM-DD HH:MM:SS"      only if the clock is wrong: it starts at 2026-01-01 and `pkg` refuses the
#                                              certificate of stafeto.github.io until it is set
#        pkg update; pkg search nginx          the index of the series 0.5 from stafeto.github.io
#        pkg install htop; TERM=vt100 htop     a package from the store in memory (the image has no
#                                              terminfo for xterm)
#        ps; cat /proc/meminfo                 nginx, nginx-fast and dropbear are running; the
#                                              memory fits the 2 GiB (the console line `frames N
#                                              MiB free` before the services shows what there is;
#                                              the full image prints no `init: free pages` line)
#   4a. The data volume (the image maps a second 2 GiB volume as /dev/sdf, made from a second snapshot that
#      carries the table of datafs and an empty file system; it is deleted with the instance; a launch gives the
#      owner nothing to do for it). The console of the first boot shows `datafs: data volume mounted, N blocks, ...`
#      with no `partition table written` and no `formatted` in it, then `datakey: no host key on /data` and
#      `datakey: host key saved to /data`. Write down the fingerprint of the console line
#      `ssh: host key SHA256:...` of step 2, then:
#        reboot (in the session on the instance, or `aws ec2 reboot-instances`)
#                                              the console line `datakey: host key restored from /data` and
#                                              the same `ssh: host key SHA256:...`; no `datafs: ... formatted`
#                                              line (the line says `data volume mounted`); `ssh` raises no host key warning
#        stop and start the instance           the same again: the volume stays attached to a stopped
#                                              instance, the fingerprint is the same
#      A volume attached after the boot is not used until the next boot (`datafs` connects once).
#   4b. One launch with the data volume left out (the fallback):
#        cargo xtask aws boot --try --no-data-volume --ami AMI --end "fast: nginx-fast on 8080" --serial 180 --session S
#      (`--no-data-volume` maps /dev/sdf to NoDevice.) The console shows `init: left out: datadisk`, `datafs: no
#      disk`, and `ssh: host key SHA256:...` made at this boot; after a reboot the fingerprint differs. The
#      page and the other servers work as before.
#   4c. The enlarged volume (issue stafeto-design#765). Launch as in step 2 with the mapping of the volume enlarged:
#        --block-device-mappings DeviceName=/dev/sdf,Ebs={VolumeSize=4,VolumeType=gp3,DeleteOnTermination=true}
#      (`aws ec2 run-instances`; the mapping changes the size and the volume still comes from the snapshot of the
#      image: the line below confirms it). The console shows, once, `datafs: backup partition table moved to the end
#      of the disk, data volume mounted, N blocks, ...` and `datakey: host key saved to /data`; after a reboot
#      `datafs: data volume mounted, ...` (no moved-table line) and `datakey: host key restored from /data` with the
#      same fingerprint. The partitions keep their size, so N is the same as in step 4a.
#   4d. A blank volume of the user's own attached as /dev/sdf. A launch mapping `/dev/sdf,Ebs={VolumeSize=1,...}`
#      merges with the snapshot mapping of the AMI (EC2 refuses a size below the snapshot's, and a larger size
#      still gives the volume of the snapshot, which is not blank), so the volume is attached after the launch:
#        cargo xtask aws boot --try --no-data-volume --ami AMI ... --session S
#        aws ec2 create-volume --size 1 --volume-type gp3 --availability-zone <the zone of the instance> (tag it as the session)
#        aws ec2 attach-volume --device /dev/sdf --instance-id I --volume-id V
#        stop and start the instance
#      The volume reads as a fresh one does (the first 4 KiB zero, bytes after), so after the start the console shows
#        datafs: foreign at sector S offset O                    (S is 8 or a later sector, for the measured volumes)
#        datafs: lba1 zero lba-last zero
#        datafs: the disk holds something else, left alone and unused in this release
#      and no line of partitioning or formatting, `ssh: host key SHA256:...` made at this boot (the fingerprint
#      differs after a reboot), nothing restarts. No byte of the volume is on the console. Also in every build:
#      `nvme: dma queues 0x... cells 0x...` once, and `nvme: io error cid C sct/sc ... slba L` on the first errors.
#      The probes of these lines on QEMU: `cargo xtask nvme-persist key image`, `key image grown`, `key foreign`.
#   4e. The checklist of the verification on EC2 (one image, four launches, then the cleaning):
#        default launch            mounts on the first boot (step 4a); the same key after stop and start
#        sdf VolumeSize=4          the moved-table line once, then the mount (step 4c); the key persists
#        a blank volume as sdf     launched with --no-data-volume, the volume created and attached, stop and start:
#                                  left alone (step 4d)
#        --no-data-volume          unchanged (step 4b)
#        clean and sweep           `cargo xtask aws clean --session S`, then `cargo xtask aws sweep`: nothing of the
#                                  project remains, the two snapshots of the image included once the image is
#                                  deregistered by `clean`
#   5. Ten minutes of curl in a loop against 80, 443 and 8080: no `ena: reset` line, the
#      keep-alive counters go on (`ena: keepalive N`).
#
#   6. The scan (issue stafeto-design#764: one request failed, once, right after a SYN scan). Needs `tcpdump` and
#      `sudo` without a password on the operator's host (the packets seen there are the ones the instance
#      sent: a reset from the instance and one from the operator's own network look alike at the client).
#      A build of 0.5.1 or later says the counters of the network service on the console (`aws ec2
#      get-console-output --latest`, a few minutes behind): `net: queues syn_dropped N queue_reaped N
#      embryo_recycled N` and `net: queues sockets U of L demux D listen_short N key_stale N syn_stray N
#      orphan_reused N set_barred N`, one baseline line about 30 s after the first request of a boot and a
#      new one at most every 30 s (and only when a counter changed) after a request, and per listening port
#      `net: listener place P port 443 syn_dropped N queue_reaped N embryo_recycled N` when one is not 0.
#      `key_stale` counts SYNs that took a queue socket that still held the key of an earlier connection
#      (the cause fixed for 764); it is the number to compare with the failures.
#      For each scan S in: `nmap -Pn -sS -p 1-65535 ADDRESS`, `nmap -Pn -sU --top-ports 200 ADDRESS`, `nmap -Pn -sS -p 1-1024 ADDRESS`
#      (the first and third twice), with ADDRESS the public address:
#        a. Read the console and write down the three `net: queues` lines (the counters before).
#        b. Start the capture in a second terminal and leave it until the request below is done:
#             sudo tcpdump -i any -n -s 96 -w target/aws/S/scan-N.pcap host ADDRESS
#        c. Run the scan. Do not wait for it to end if nmap runs long (`--host-timeout 200s`).
#        d. At once, in the same shell line as the end of the scan (no pause), ONE request to each of
#           80, 443 and 8080 and one ssh login, each with its own exit code and message kept:
#             curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' http://ADDRESS/
#             curl -sSk -o /dev/null -w '%{http_code} %{time_total}\n' https://ADDRESS/
#             curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' http://ADDRESS:8080/
#             ssh -i target/aws/S/try-key -o BatchMode=yes user@ADDRESS true
#           and, before the scan, a session that stays open and is used after it:
#             ssh -i target/aws/S/try-key user@ADDRESS 'while :; do date; sleep 1; done'  (output redirected to a file)
#        e. Stop the capture. Read the console again (after about a minute; make one more request to
#           trigger the line) and write down the three lines (the counters after).
#      Repeat until a request fails, or twenty times in all. A failed request is read in the capture:
#        - `tcpdump -nn -r scan-N.pcap 'tcp[tcpflags] & tcp-rst != 0 and src ADDRESS'` lists every reset
#          the instance sent: a failure caused by the instance shows one answering the ACK or the first
#          data segment of that connection (source port of curl), within a round trip of the SYN-ACK. The
#          stale-key cause shows SYN, SYN-ACK, ACK, then RST from the instance with seq equal to the ACK
#          number of the client's first data segment (an RST to an ACK that no socket holds).
#        - A SYN with no SYN-ACK and a retransmission one second later: a queue without room (look at
#          `syn_dropped` growing).
#        - No RST from the instance and a RST from another address, or no answer at all: the operator's
#          network (the table of a router or of the host's firewall full after a scan) is the cause and
#          the instance is clear; `sudo pfctl -si` shows the states on macOS.
#      A pass: twenty scans of each kind, no first request failed, the long-lived ssh session answered
#      through every scan, `key_stale` is counted when the earlier failures were of this kind.
#
# End of the session: `cargo xtask aws clean --session S` terminates the instance and removes the group and the key pair.
echo "see the comments of this file: the steps and the expected console lines"
