#include <sys/types.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <net/if.h>

#define BATCH_SIZE 16


typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;


struct xdp_umem_uqueue {
  u32 cached_prod;
  u32 cached_cons;
  u32 mask;
  u32 size;
  u32 *producer;
  u32 *consumer;
  u64 *ring;
  void *map;
};

struct xdp_umem {
  char *frames;
  struct xdp_umem_uqueue fq;
  struct xdp_umem_uqueue cq;
  int fd;
};

struct xdp_uqueue {
  u32 cached_prod;
  u32 cached_cons;
  u32 mask;
  u32 size;
  u32 *producer;
  u32 *consumer;
  struct xdp_desc *ring;
  void *map;
};

struct xdpsock {
  struct xdp_uqueue rx;
  struct xdp_uqueue tx;
  int sfd;
  struct xdp_umem *umem;
  u32 outstanding_tx;
};

struct sock_port{
  struct xdpsock *xdps_in;
  struct xdpsock *xdps_out;
  int id;
};


struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue, int ifindex, u32 xdp_bind_flag);

int XDPGet(struct sock_port *sp, struct xdp_desc *descs);
int XDPPut(struct sock_port *sp, struct xdp_desc *descs, int *pass_flags, unsigned int rcvd, unsigned int *idx);
