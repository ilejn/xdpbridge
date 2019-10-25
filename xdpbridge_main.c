#include "xdpbridge_user.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <string.h>

#include <errno.h>
#include <libgen.h>
#include <signal.h>


#include <sys/resource.h>

#include "bpf_load.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include <getopt.h>
#include <pthread.h>



#include "xdpbridge.h"

#ifndef XDP_ZEROCOPY
#define XDP_ZEROCOPY  (1 << 2) /* Force zero-copy mode */
#endif


static int opt_iifindex;
static int opt_oifindex;
static int opt_queues = 1;
static int opt_bidirectional = 0;

#define MAX_TRANSMIT_QUEUES 128
static int opt_transmit_queues[MAX_TRANSMIT_QUEUES];
static int opt_transmit_queue_num = 0;


static const char *opt_iif = "";
static const char *opt_oif = "";

static u32 opt_xdp_i_bind_flags;
static u32 opt_xdp_i_flags;
static u32 opt_xdp_o_bind_flags;
static u32 opt_xdp_o_flags;


static struct option long_options[] = {
  {"client-interface", required_argument, 0, 'i'},
  {"world-interface", required_argument, 0, 'o'},
  {"queues", required_argument, 0, 'q'},
  {"bidirectional", no_argument, 0, 'b'},
  {"transmit-queue", required_argument, 0, 't'},
  {"xdp-skb-client", no_argument, 0, 'S'},
  {"xdp-native-client", no_argument, 0, 'N'},
  {"xdp-zerocopy-client", no_argument, 0, 'Z'},
  {"xdp-skb-world", no_argument, 0, 's'},
  {"xdp-native-world", no_argument, 0, 'n'},
  {"xdp-zerocopy-world", no_argument, 0, 'z'},
  {0, 0, 0, 0}
};

static void usage(const char *prog)
{
  const char *str =
    "  Usage: %s [OPTIONS]\n"
    "  Options :\n"
    "  -i, --client-interface=input_iface Client interface\n"
    "  -o, --world-interface=output_iface World interface\n"
    "  -q, --queues=n Number of client-side incoming queues and threads (default 1)\n"
    "  -t, --transmit-queue=n Transmit queue (can be set multiple times)\n"
    "  -b, --bidirectional  Transfer packets from world to client as well\n"
    "  -S, --xdp-skb-client Enforce XDP skb-mod for client interface\n"
    "  -N, --xdp-native-client  Enforce XDP native mode for client interface\n"
    "  -Z, --xdp-zerocopy-client  Enforce XDP zerocopy for client interface\n"
    "  -C, --xdp-copy-client  Enforce XDP copy for client interface\n"
    "  -s, --xdp-skb-world Enforce XDP skb-mod for world interface\n"
    "  -n, --xdp-native-world Enforce XDP native mode for world interface\n"
    "  -z, --xdp-zerocopy-world Enforce XDP zerocopy for world interface\n"
    "  -c, --xdp-copy-world Enforce XDP copy for world interface\n"
    "\n";
  fprintf(stderr, str, prog);
  exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
  int option_index, c;

  opterr = 0;

  for (;;) {

    c = getopt_long(argc, argv, "i:o:q:t:bSNZCsnzc", long_options,
        &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'i':
      opt_iif = optarg;
      break;
    case 'o':
      opt_oif = optarg;
      break;
    case 'q':
      opt_queues = atoi(optarg);
      break;
    case 't':
      opt_transmit_queues[opt_transmit_queue_num++] = atoi(optarg);
      break;
    case 'b':
      opt_bidirectional = 1;
      break;
    case 'S':
      opt_xdp_i_flags |= XDP_FLAGS_SKB_MODE;
      break;
    case 'N':
      opt_xdp_i_flags |= XDP_FLAGS_DRV_MODE;
      break;
    case 'Z':
      opt_xdp_i_bind_flags |= XDP_ZEROCOPY;
      break;
    case 'C':
      opt_xdp_i_bind_flags |= XDP_COPY;
      break;
    case 's':
      opt_xdp_o_flags |= XDP_FLAGS_SKB_MODE;
      break;
    case 'n':
      opt_xdp_o_flags |= XDP_FLAGS_DRV_MODE;
      break;
    case 'z':
      opt_xdp_o_bind_flags |= XDP_ZEROCOPY;
      break;
    case 'c':
      opt_xdp_o_bind_flags |= XDP_COPY;
      break;
    default:
      usage(basename(argv[0]));
    }
  }

  opt_iifindex = if_nametoindex(opt_iif);
  if (!opt_iifindex) {
    fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
      opt_iif);
    usage(basename(argv[0]));
  }
  opt_oifindex = if_nametoindex(opt_oif);
  if (!opt_oifindex) {
    fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
      opt_oif);
    usage(basename(argv[0]));
  }
}

// pass all packets
//   app logic stub
static void validate_packets(struct xdp_desc* desc, int *pass_flags, unsigned int rcvd)
{
  unsigned int i = 0;
  for (; i < rcvd; ++i) {
    pass_flags[i] = true;
  }
}

static void * XDPRequestHandler(void *arg)
{
  struct sock_port *sp = (struct sock_port*) arg;
  unsigned int idx = 0;
  struct xdp_desc descs[BATCH_SIZE];
  int pass_flags[BATCH_SIZE];
  for (;;) {

    unsigned int rcvd = XDPGet(sp, descs);
    validate_packets(descs, pass_flags, rcvd);

    if (rcvd) {
      XDPPut(sp, descs, pass_flags, rcvd, &idx);
    }
  }
  free(sp);
}

int main(int argc, char **argv)
{
  struct xdpsock *xsks[MAX_QUEUES];
  sigset_t ss;

  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  // struct bpf_prog_load_attr prog_load_attr = {
  //  .prog_type  = BPF_PROG_TYPE_XDP,
  // };
  // int prog_fd, xdp_bridge_prog_fd, xdp_redirect_map_prog_fd;
  // int xsks_map, num_queues_map;
  char xdp_filename[256];
  // struct bpf_map *map;
  int q, key = 0, ret;
  struct sock_port *sp = NULL;

  struct xdp_umem* umem_arr[MAX_QUEUES];
  pthread_t pt[MAX_QUEUES];

  parse_command_line(argc, argv);

  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
      strerror(errno));
    exit(EXIT_FAILURE);
  }

  snprintf(xdp_filename, sizeof(xdp_filename), "%s_kern.o", argv[0]);

  if (load_bpf_file(xdp_filename)) {
    fprintf(stderr, "ERROR: no program found: %s\n",
            xdp_filename);
    exit(EXIT_FAILURE);
  }

  if (!prog_fd[0]) {
    fprintf(stderr, "load_bpf_file: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (bpf_set_link_xdp_fd(opt_iifindex, prog_fd[0], opt_xdp_i_flags) < 0) {
    fprintf(stderr, "ERROR: input link set xdp fd failed\n");
    exit(EXIT_FAILURE);
  }

  if (opt_bidirectional) {
    if (bpf_set_link_xdp_fd(opt_oifindex, prog_fd[1], opt_xdp_o_flags) < 0) {
      fprintf(stderr, "ERROR: output link set xdp fd failed\n");
      exit(EXIT_FAILURE);
    }
  }

  memset(umem_arr, 0, sizeof(umem_arr));
  fprintf(stderr, "Let's create Sockets!\n");

  /* Create sockets... */
  for (q = 0; q < opt_queues; q++) { // q -> queue
    int outgoing_q, outgoing_q_ind = 0;

    xsks[q] = xsk_configure(NULL, q, opt_iifindex, opt_xdp_i_bind_flags);

    ret = bpf_map_update_elem(map_fd[0], &q, &xsks[q]->sfd, 0);
    if (ret) {
      fprintf(stderr, "Error: bpf_map_update_elem %d\n", q);
      fprintf(stderr, "ERRNO: %d\n", errno);
      fprintf(stderr, "%s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    // Configure and start the consumer thread
    sp = malloc(sizeof(struct sock_port));
    sp->xdps_in = xsks[q];

    if (opt_transmit_queue_num) {
      outgoing_q_ind = q % opt_transmit_queue_num;
      outgoing_q = opt_transmit_queues[outgoing_q_ind];
    } else {
      // outgoing queue has same num as incoming
      outgoing_q = outgoing_q_ind = q;
    }

    sp->xdps_out = xsk_configure(umem_arr[outgoing_q_ind], outgoing_q, opt_oifindex, opt_xdp_o_bind_flags);
    umem_arr[outgoing_q_ind] = sp->xdps_out->umem;

    sp->id = q;
    fprintf(stderr, "Socket %d created\n", q);
    pthread_create(&pt[q], NULL, XDPRequestHandler, sp);

  }
  fprintf(stderr, "Started %d Threads\n", opt_queues);

  // Set the number of queues
  ret = bpf_map_update_elem(map_fd[1], &key, &opt_queues, 0);
  if (ret) {
    fprintf(stderr, "Error: bpf_map_update_elem\n");
    fprintf(stderr, "ERRNO: %d\n", errno);
    fprintf(stderr, "%s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (opt_bidirectional) {
    // Set outgoing interface for w=>c kernelspace path
    ret = bpf_map_update_elem(map_fd[2], &key, &opt_iifindex, 0);
    if (ret) {
      fprintf(stderr, "Error: bpf_map_update_elem\n");
      fprintf(stderr, "ERRNO: %d\n", errno);
      fprintf(stderr, "%s", strerror(errno));
      exit(EXIT_FAILURE);
    }
  }

  sigfillset(&ss);
  sigprocmask(SIG_BLOCK, &ss, 0);
  sigwaitinfo(&ss, NULL);

  fprintf(stderr, "Exiting\n");

  bpf_set_link_xdp_fd(opt_iifindex, -1, opt_xdp_i_flags);
  if (opt_bidirectional) {
    bpf_set_link_xdp_fd(opt_oifindex, -1, opt_xdp_o_flags);
  }

  return 0;
}
