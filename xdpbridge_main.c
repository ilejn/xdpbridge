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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include <getopt.h>
#include <pthread.h>



#include "xdpbridge.h"

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"output", required_argument, 0, 'o'},
	{"queues", required_argument, 0, 'q'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -i, --interface=foo	Input interface foo\n"
		"  -o, --output=bar	Output interface bar\n"
		"  -q, --queues=n	Number of queues (defaults to 1)\n"
		"  -S, --xdp-skb=n	Use XDP skb-mod\n"
		"  -N, --xdp-native=n	Enfore XDP native mode\n"
		"\n";
	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}


static void int_exit(int sig)
{
	(void)sig;
	bpf_set_link_xdp_fd(opt_iifindex, -1, opt_xdp_flags);
	exit(EXIT_SUCCESS);
}


static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:o:q:SNt:", long_options,
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
		case 'S':
			opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
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


static unsigned long prev_time;

// static unsigned int header_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);




static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}


int main(int argc, char **argv)
{
  struct xdpsock *xsks[MAX_QUEUES];


	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd, xsks_map, num_queues_map;
	struct bpf_object *obj;
	char xdp_filename[256];
	struct bpf_map *map;
	int q, key = 0, ret;
	struct sock_port *sp = NULL;

	pthread_t pt[MAX_QUEUES];

	parse_command_line(argc, argv);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(xdp_filename, sizeof(xdp_filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = xdp_filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		exit(EXIT_FAILURE);
	}

	map = bpf_object__find_map_by_name(obj, "xsks_map");
	xsks_map = bpf_map__fd(map);
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
		exit(EXIT_FAILURE);
	}

	map = bpf_object__find_map_by_name(obj, "num_queues_map");
	num_queues_map = bpf_map__fd(map);
	if (num_queues_map < 0) {
		fprintf(stderr, "ERROR: no num_queues map found: %s\n",
			strerror(num_queues_map));
		exit(EXIT_FAILURE);
	}

	// map = bpf_object__find_map_by_name(obj, "rr_map");
	// rr_map = bpf_map__fd(map);
	// if (rr_map < 0) {
	// 	fprintf(stderr, "ERROR: no rr map found: %s\n",
	// 		strerror(rr_map));
	// 	exit(EXIT_FAILURE);
	// }

	if (bpf_set_link_xdp_fd(opt_iifindex, prog_fd, opt_xdp_flags) < 0) {
		fprintf(stderr, "ERROR: link set xdp fd failed\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Let's create Sockets!\n");

	/* Create sockets... */
  for (q = 0; q < opt_queues; q++) { // q -> queue
    // pqt = create_socket(q);
    xsks[q] = xsk_configure(NULL, q, opt_iifindex);

    // if ( pqt < 0 ) {
    //   fprintf(stderr,
    //           "ERROR: Socket creation failed\n");
    //   exit(EXIT_FAILURE);
    // }
    ret = bpf_map_update_elem(xsks_map, &q, &xsks[q]->sfd, 0);
    if (ret) {
      fprintf(stderr, "Error: bpf_map_update_elem %d\n", q);
      fprintf(stderr, "ERRNO: %d\n", errno);
      fprintf(stderr, "%s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    // Configure and start the consumer thread
    sp = malloc(sizeof(struct sock_port));
    sp->xdps_in = xsks[q];
    sp->xdps_out = xsk_configure(NULL, q, opt_oifindex);
    sp->id = q;
    fprintf(stderr, "Socket %d created\n", q);
    pthread_create(&pt[q], NULL, XDPRequestHandler, sp);

    // if (t == 0) {
    //   // Set the number of threads per queue
    //   ret = bpf_map_update_elem(num_socks_map, &pqt, &opt_threads, 0);
    //   if (ret) {
    //     fprintf(stderr, "Error: bpf_map_update_elem %d\n", pqt);
    //     fprintf(stderr, "ERRNO: %d\n", errno);
    //     fprintf(stderr, "%s", strerror(errno));
    //     exit(EXIT_FAILURE);
    //   }
    // }
	}
  fprintf(stderr, "Started %d Threads\n", opt_queues);

	// Set the number of queues
	ret = bpf_map_update_elem(num_queues_map, &key, &opt_queues, 0);
	if (ret) {
		fprintf(stderr, "Error: bpf_map_update_elem\n");
		fprintf(stderr, "ERRNO: %d\n", errno);
		fprintf(stderr, "%s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	// signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();

	sleep(72000); //Sleep for 20 hours

	return 0;
}
