/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The options of the Dropbear build of packages/dropbear.toml, over the
 * defaults of default_options.h. */

#ifndef LOCALOPTIONS_H_
#define LOCALOPTIONS_H_

/* One process for each connection by fork alone: no second exec of the
 * server (it would need /proc/self/exe). */
#define DROPBEAR_REEXEC 0

/* The image has no sftp-server, no X server and no agent. */
#define DROPBEAR_SFTPSERVER 0
#define DROPBEAR_SVR_AGENTFWD 0
#define DROPBEAR_CLI_AGENTFWD 0
#define DROPBEAR_X11FWD 0

/* Nothing is compiled in that the image does not use: no password login (the key is the only
 * way in) and no port forwarding of any kind. The server still gets -s, -j and -k. */
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_LOCALTCPFWD 0
#define DROPBEAR_SVR_REMOTETCPFWD 0
#define DROPBEAR_SVR_LOCALSTREAMFWD 0
#define DROPBEAR_SVR_REMOTESTREAMFWD 0

/* Each connection that has not authenticated is a forked child, and `fork` of the system
 * copies the whole address space: few of them, for a short time, and few tries. */
#define MAX_UNAUTH_CLIENTS 4
#define MAX_UNAUTH_PER_IP 2
#define AUTH_TIMEOUT 30
#define MAX_AUTH_TRIES 3

/* No message of the day. */
#define DO_MOTD 0

#endif /* LOCALOPTIONS_H_ */
