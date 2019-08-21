AF_XDP based bridge
===================

Transfers L2 packets from one interface to another as is
with the help of AF_XDP technology https://www.kernel.org/doc/html/v4.18/networking/af_xdp.html

Both interfaces have to have same number of queues (a packet from Nth incoming queue
is put to Nth outgoing queue).

Usage
-----

./build/xdpbridge/xdpbridge -h
  Usage: xdpbridge [OPTIONS]
  Options:
  -i, --interface=foo	Input interface foo
  -o, --output=bar	Output interface bar
  -q, --queues=n	Number of queues (default 1)
  -S, --xdp-skb=n	Use XDP skb-mod
  -N, --xdp-native=n	Enforce XDP native mode

Building from source
--------------------

mkdir build
cd build
cmake .. -DKERNEL_TOP=/top/of/kernel/sources
make

Requirements
------------
*  kernel sources (tested against 4.18)
*  run `make headers_install` beforehand
*  clang and gcc (clang is mandatory, gcc might be not needed)
*  cmake
