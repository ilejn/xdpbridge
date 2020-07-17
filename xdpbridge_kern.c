// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "xdpbridge"
#include <linux/bpf.h>
#include <asm/byteorder.h>

#include "bpf_helpers.h"
#include "xdpbridge.h"

struct bpf_map_def SEC("maps") xsks_client_map = {
  .type = BPF_MAP_TYPE_XSKMAP,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(int),
  .max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") num_queues_client_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(uint16_t),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") xsks_world_map = {
  .type = BPF_MAP_TYPE_XSKMAP,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(int),
  .max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") num_queues_world_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(unsigned int),
  .value_size = sizeof(uint16_t),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") tx_port = {
  .type = BPF_MAP_TYPE_DEVMAP,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 100,  // Why not "1" ?
};

SEC("xdp_sock_client")
int xdp_sock_client_prog(struct xdp_md *ctx)
{
  unsigned int offset = 0;
  uint16_t *num_queues;

  num_queues = bpf_map_lookup_elem(&num_queues_client_map, &offset);
  if (!num_queues)
    return XDP_ABORTED;
  if (*num_queues > 1) {
    offset = ctx->rx_queue_index % *num_queues;
  }

  /* Forward c=>w packet to xsks Socket */
  return bpf_redirect_map(&xsks_client_map, offset, 0);
}

SEC("xdp_sock_world")
int xdp_sock_world_prog(struct xdp_md *ctx)
{
  unsigned int offset = 0;
  uint16_t *num_queues;

  num_queues = bpf_map_lookup_elem(&num_queues_world_map, &offset);
  if (!num_queues)
    return XDP_ABORTED;
  if (*num_queues > 1) {
    offset = ctx->rx_queue_index % *num_queues;
  }

  /* Forward w=>c packet to xsks Socket */
  return bpf_redirect_map(&xsks_world_map, offset, 0);
}

SEC("xdp_redirect_map")
int xdp_redirect_map_prog(struct xdp_md *ctx)
{
  /* constant virtual port - consider decoupling */
  int vport = 0;

  /* send w=>c packet out physical port */
  return bpf_redirect_map(&tx_port, vport, 0);
}

char _license[] SEC("license") = "GPL";
