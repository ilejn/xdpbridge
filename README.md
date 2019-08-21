AF_XDP based bridge
===================

Transfers packets from one interface to another with the help of
AF_XDP technology https://www.kernel.org/doc/html/v4.18/networking/af_xdp.html

Both interfaces have to have same number of queues (a packet from Nth incoming queue
is put to Nth outgoing queue).
