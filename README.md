AF_XDP based bridge
===================

Transfers L2 packets between two interfaces (in both directions) as is
with the help of AF_XDP technology https://www.kernel.org/doc/html/v4.18/networking/af_xdp.html

Packets from client to world travel via userspace and can be controlled (find *validate_packets*,
   an application logic stub).
Packets from world to client travel via kernelspace only.

Usage
-----

``` shell
# ./build/xdpbridge/xdpbridge -h
  Usage: xdpbridge [OPTIONS]
  Options :
  -i, --client-interface=input_iface	Client interface
  -o, --world-interface=output_iface	World interface
  -q, --queues=n	Number of client-side incoming queues and threads (default 1)
  -t, --transmit-queue=n	Transmit queue (can be set multiple times)
  -b, --bidirectional	Transfer packets from world to client as well
  -S, --xdp-skb-client Enforce XDP skb-mod for client interface
  -N, --xdp-native-client	Enforce XDP native mode for client interface
  -Z, --xdp-zerocopy-client	Enforce XDP zerocopy for client interface
  -C, --xdp-copy-client	Enforce XDP copy for client interface
  -s, --xdp-skb-world Enforce XDP skb-mod for world interface
  -n, --xdp-native-world	Enforce XDP native mode for world interface
  -z, --xdp-zerocopy-world	Enforce XDP zerocopy for world interface
  -c, --xdp-copy-world	Enforce XDP copy for world interface
```

Thread model for c=>w part is a thread per queue.

If no *transmit-queue* is specified, Nth transmit queue (at world interface)
is used to send a packet received via Nth incoming queue (at client interface).

Note, that some hardware or drivers require that transmit queues (at world side) are dedicated, without incoming traffic,
that is why *transmit-queue* option is introduced.


Build prerequisites
-------------
* g++
* clang
* cmake
* libelf
* linux kernel tree 4.18 or 5 (make oldconfig && make prepare && make headers_install && make)

Build procedure
---------------
cmake -DKERNEL_TOP=/path/to/kernel/tree . && make
