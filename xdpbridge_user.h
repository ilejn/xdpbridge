#include <sys/types.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <net/if.h>


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


static u32 opt_xdp_flags;
static const char *opt_iif = "";
static const char *opt_oif = "";
static int opt_iifindex;
static int opt_oifindex;
static int opt_queues = 1;
static u32 opt_xdp_bind_flags;


struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue, int ifindex);
void * XDPRequestHandler(void *arg);
