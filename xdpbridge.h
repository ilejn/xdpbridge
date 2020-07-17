/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDPBRIDGE_H_
#define XDPBRIDGE_H_

/* Power-of-2 number of sockets per function */
#define MAX_SOCKS 16

#define MAX_QUEUES 64

enum XDP_MAPS {
    XSKS_CLIENT_MAP,
    NUM_QUEUES_CLIENT_MAP,
    XSKS_WORLD_MAP,
    NUM_QUEUES_WORLD_MAP,
    TX_PORT_MAP
};

enum XDP_PROGRAMS {
    XDP_SOCK_CLIENT_PROG,
    XDP_SOCK_WORLD_PROG,
    XDP_REDIRECT_MAP_PROG
};


#endif /* XDPBRIDGE_H_ */
