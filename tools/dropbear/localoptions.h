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

/* No message of the day. */
#define DO_MOTD 0

#endif /* LOCALOPTIONS_H_ */
