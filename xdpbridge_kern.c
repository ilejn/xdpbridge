// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "xdpbridge"
#include <linux/bpf.h>
#include <asm/byteorder.h>

#include "bpf_helpers.h"
#include "xdpbridge.h"

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") num_queues_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(uint16_t),
	.max_entries = 1,
};

SEC("xdp_bridge")
int xdp_sock_prog(struct xdp_md *ctx)
{
	unsigned int offset = 0;
	uint16_t *num_queues;

	num_queues = bpf_map_lookup_elem(&num_queues_map, &offset);
	if (!num_queues)
		return XDP_ABORTED;
	if (*num_queues > 1) {
		offset = ctx->rx_queue_index % *num_queues;
	}

	/* Forward Packet to xsks Socket */
	return bpf_redirect_map(&xsks_map, offset, 0);
}

char _license[] SEC("license") = "GPL";
