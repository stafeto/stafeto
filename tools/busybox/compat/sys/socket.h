// SPDX-License-Identifier: MIT
#ifndef STAFETO_SOCKET_H
#define STAFETO_SOCKET_H
#include <stdint.h>
#include <sys/types.h>
typedef unsigned socklen_t;
typedef unsigned short sa_family_t;
struct sockaddr { sa_family_t sa_family; char sa_data[14]; };
struct in_addr { uint32_t s_addr; };
struct sockaddr_in { sa_family_t sin_family; uint16_t sin_port; struct in_addr sin_addr; char sin_zero[8]; };
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RDM 4
#define SOCK_SEQPACKET 5
#define SOCK_RAW 3
#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
int socket(int, int, int);
int bind(int, const struct sockaddr *, socklen_t);
int listen(int, int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
#endif
