	/* Copyright(c) 2017 - 2018 Intel Corporation. */

#include <assert.h>
#include <errno.h>

#include "xdpbridge_user.h"


#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>


#include <poll.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "xdpbridge.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES 131072
#define FRAME_HEADROOM 0
#define FRAME_SHIFT 11
#define FRAME_SIZE 2048
#define NUM_DESCS 1024
#define BATCH_SIZE 16

#define FQ_NUM_DESCS 1024
#define CQ_NUM_DESCS 1024


#define lassert(expr)							\
	do {								\
		if (!(expr)) {						\
			fprintf(stderr, "%s:%s:%i: Assertion failed: "	\
				#expr ": errno: %d/\"%s\"\n",		\
				__FILE__, __func__, __LINE__,		\
				errno, strerror(errno));		\
			abort();                      \
		}							\
	} while (0)

#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline u32 umem_nb_free(struct xdp_umem_uqueue *q, u32 nb)
{
	u32 free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;

	return q->cached_cons - q->cached_prod;
}

static inline u32 xq_nb_free(struct xdp_uqueue *q, u32 ndescs)
{
	u32 free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= ndescs)
		return free_entries;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;
	return q->cached_cons - q->cached_prod;
}

static inline u32 umem_nb_avail(struct xdp_umem_uqueue *q, u32 nb)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}

static inline u32 xq_nb_avail(struct xdp_uqueue *q, u32 ndescs)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > ndescs) ? ndescs : entries;
}

static inline int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, u64 *d,
				      size_t nb)
{
	u32 i;

	if (umem_nb_free(fq, nb) < nb)
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		u32 idx = fq->cached_prod++ & fq->mask;

		fq->ring[idx] = d[i];
	}

	u_smp_wmb();

	*fq->producer = fq->cached_prod;

	return 0;
}

static inline int umem_fill_to_kernel_ex(struct xdp_umem_uqueue *fq,
					 struct xdp_desc *d,
					 size_t nb)
{
	u32 i;

	if (umem_nb_free(fq, nb) < nb)
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		u32 idx = fq->cached_prod++ & fq->mask;

		fq->ring[idx] = d[i].addr;
	}

	u_smp_wmb();

	*fq->producer = fq->cached_prod;

	return 0;
}


static inline size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq,
					       u64 *d, size_t nb)
{
	u32 idx, i, entries = umem_nb_avail(cq, nb);

	u_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = cq->cached_cons++ & cq->mask;
		d[i] = cq->ring[idx];
	}

	if (entries > 0) {
		u_smp_wmb();

		*cq->consumer = cq->cached_cons;
	}

	return entries;
}

static inline void *xq_get_data(struct xdpsock *xsk, u64 addr)
{
	return &xsk->umem->frames[addr];
}

static inline int xq_enq_copy(struct xdpsock *xsk_in,
       struct xdpsock *xsk_out,
       unsigned int id,
       struct xdp_uqueue *uq,
			 const struct xdp_desc *descs,
			 unsigned int ndescs)
{
	struct xdp_desc *r = uq->ring;
	unsigned int i;

  // fprintf(stderr, "xq_enq\n");

	if (xq_nb_free(uq, ndescs) < ndescs)
		return -ENOSPC;

  // while(xq_nb_free(uq, ndescs) < ndescs)
  // {}

	for (i = 0; i < ndescs; i++) {
		u32 idx = uq->cached_prod++ & uq->mask;
    char *pkt = NULL;



    pkt = xq_get_data(xsk_in, descs[i].addr);

		// r[idx].addr = descs[i].addr;
    r[idx].addr = (id + i) << FRAME_SHIFT;
		r[idx].len = descs[i].len;

    memcpy(&xsk_out->umem->frames[r[idx].addr/*idx*/], pkt, descs[i].len);
    // fprintf(stderr, "addr %lld, %d\n", r[idx].addr, idx);

    // hex_dump(pkt, r[idx].len, r[idx].len);

	}

	u_smp_wmb();

	*uq->producer = uq->cached_prod;
	return 0;
}

static inline int xq_deq(struct xdp_uqueue *uq,
			 struct xdp_desc *descs,
			 int ndescs)
{
	struct xdp_desc *r = uq->ring;
	unsigned int idx;
	int i, entries;

	entries = xq_nb_avail(uq, ndescs);

	u_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = uq->cached_cons++ & uq->mask;
		descs[i] = r[idx];
	}

	if (entries > 0) {
		u_smp_wmb();

		*uq->consumer = uq->cached_cons;
	}

	return entries;
}

static struct xdp_umem *xdp_umem_configure(int sfd)
{
	int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
	struct xdp_mmap_offsets off;
	struct xdp_umem_reg mr;
	struct xdp_umem *umem;
	socklen_t optlen;
	void *bufs;

	umem = calloc(1, sizeof(*umem));
	lassert(umem);

	lassert(posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
			       NUM_FRAMES * FRAME_SIZE) == 0);

	mr.addr = (__u64)bufs;
	mr.len = NUM_FRAMES * FRAME_SIZE;
	mr.chunk_size = FRAME_SIZE;
	mr.headroom = FRAME_HEADROOM;

	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size,
			   sizeof(int)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size,
			   sizeof(int)) == 0);

	optlen = sizeof(off);
	lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
			   &optlen) == 0);

	umem->fq.map = mmap(0, off.fr.desc +
			    FQ_NUM_DESCS * sizeof(u64),
			    PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_POPULATE, sfd,
			    XDP_UMEM_PGOFF_FILL_RING);
	lassert(umem->fq.map != MAP_FAILED);

	umem->fq.mask = FQ_NUM_DESCS - 1;
	umem->fq.size = FQ_NUM_DESCS;
	umem->fq.producer = umem->fq.map + off.fr.producer;
	umem->fq.consumer = umem->fq.map + off.fr.consumer;
	umem->fq.ring = umem->fq.map + off.fr.desc;
	umem->fq.cached_cons = FQ_NUM_DESCS;

	umem->cq.map = mmap(0, off.cr.desc +
			     CQ_NUM_DESCS * sizeof(u64),
			     PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_POPULATE, sfd,
			     XDP_UMEM_PGOFF_COMPLETION_RING);
	lassert(umem->cq.map != MAP_FAILED);

	umem->cq.mask = CQ_NUM_DESCS - 1;
	umem->cq.size = CQ_NUM_DESCS;
	umem->cq.producer = umem->cq.map + off.cr.producer;
	umem->cq.consumer = umem->cq.map + off.cr.consumer;
	umem->cq.ring = umem->cq.map + off.cr.desc;

	umem->frames = bufs;
	umem->fd = sfd;

	return umem;
}

struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue, int ifindex)
{
	struct sockaddr_xdp sxdp = {};
	struct xdp_mmap_offsets off;
	int sfd, ndescs = NUM_DESCS;
	struct xdpsock *xsk;
	bool shared = true;
	socklen_t optlen;
	u64 i;

  fprintf(stderr, "configure for queue %d\n", queue);

	sfd = socket(PF_XDP, SOCK_RAW, 0);
	lassert(sfd >= 0);

	xsk = calloc(1, sizeof(*xsk));
	lassert(xsk);

	xsk->sfd = sfd;
	xsk->outstanding_tx = 0;

	if (!umem) {
		shared = false;
		xsk->umem = xdp_umem_configure(sfd);
	} else {
		xsk->umem = umem;
	}

	lassert(setsockopt(sfd, SOL_XDP, XDP_RX_RING,
			   &ndescs, sizeof(int)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_TX_RING,
			   &ndescs, sizeof(int)) == 0);
	optlen = sizeof(off);
	lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
			   &optlen) == 0);

	/* Rx */
	xsk->rx.map = mmap(NULL,
			   off.rx.desc +
			   NUM_DESCS * sizeof(struct xdp_desc),
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, sfd,
			   XDP_PGOFF_RX_RING);
	lassert(xsk->rx.map != MAP_FAILED);

	if (!shared) {
		for (i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE)
			lassert(umem_fill_to_kernel(&xsk->umem->fq, &i, 1)
				== 0);
	}

	/* Tx */
	xsk->tx.map = mmap(NULL,
			   off.tx.desc +
			   NUM_DESCS * sizeof(struct xdp_desc),
			   PROT_READ | PROT_WRITE,
         MAP_SHARED | MAP_POPULATE, sfd/*osfd*/,
			   XDP_PGOFF_TX_RING);
	lassert(xsk->tx.map != MAP_FAILED);

	xsk->rx.mask = NUM_DESCS - 1;
	xsk->rx.size = NUM_DESCS;
	xsk->rx.producer = xsk->rx.map + off.rx.producer;
	xsk->rx.consumer = xsk->rx.map + off.rx.consumer;
	xsk->rx.ring = xsk->rx.map + off.rx.desc;

	xsk->tx.mask = NUM_DESCS - 1;
	xsk->tx.size = NUM_DESCS;
	xsk->tx.producer = xsk->tx.map + off.tx.producer;
	xsk->tx.consumer = xsk->tx.map + off.tx.consumer;
	xsk->tx.ring = xsk->tx.map + off.tx.desc;
	xsk->tx.cached_cons = NUM_DESCS;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;

	if (shared) {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->fd;
	} else {
		sxdp.sxdp_flags = opt_xdp_bind_flags;
	}

  fprintf(stderr, "Configuring queue %d, in fd %d(%d), out fd %d(%d)\n", queue, opt_iifindex, sfd, opt_oifindex, sfd);
	lassert(bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0);

	return xsk;
}



static void kick_tx(int fd)
{
	int ret;

  // fprintf(stderr, "kick_tx\n");

	ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return;
	lassert(0);
}

static inline void complete_tx(struct xdpsock *xsk)
{
	u64 descs[BATCH_SIZE];
	unsigned int rcvd;
	size_t ndescs;

  // fprintf(stderr, "complete_tx\n");

	if (!xsk->outstanding_tx)
		return;
  // fprintf(stderr, "outstanding_tx\n");

	kick_tx(xsk->sfd);
	ndescs = (xsk->outstanding_tx > BATCH_SIZE) ? BATCH_SIZE :
		 xsk->outstanding_tx;

	// re-add completed Tx buffers
	rcvd = umem_complete_from_kernel(&xsk->umem->cq, descs, ndescs);
	if (rcvd > 0) {

		// umem_fill_to_kernel(&xsk->umem->fq, descs, rcvd);

		xsk->outstanding_tx -= rcvd;
    // fprintf(stderr, "xsk->outstanding_tx %d\n", xsk->outstanding_tx);
	}
}

void * XDPRequestHandler(void *arg)
{
	int timeout = 1000, ret = 0;
	struct sock_port *sp = (struct sock_port*) arg;
	struct xdp_desc descs[BATCH_SIZE];
	unsigned int rcvd, i;
	unsigned int idx = 0;

	struct pollfd pfd[1];
	memset(&pfd, 0, sizeof(pfd));

  pfd->fd = sp->xdps_in->sfd;
  pfd->events = POLLIN;

	for (;;) {
    // fprintf(stderr, "before xq_deq\n");
    rcvd = xq_deq(&sp->xdps_in->rx, descs, BATCH_SIZE);
    if (rcvd == 0)
      continue;
    // fprintf(stderr, "after xq_deq\n");

    // Back to the Kernel by TX
    do {
      ret = xq_enq_copy(sp->xdps_in, sp->xdps_out, idx, &sp->xdps_out->tx, descs, rcvd);
      if (!ret) {

        umem_fill_to_kernel_ex(&sp->xdps_in->umem->fq, descs, rcvd);

        sp->xdps_out->outstanding_tx += rcvd;

        idx += rcvd;
        idx %= NUM_FRAMES;
      }
      // Complete the TX
      complete_tx(sp->xdps_out);
    } while (ret == -ENOSPC);
	}
	// free(sp->xdps);
	free(sp);
  return 0;
}
