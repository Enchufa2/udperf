/*
 * udperf: a UDP-only advanced iperf
 * Copyright(c) 2013-2016 by Iñaki Ucar <i.ucar86@gmail.com>
 * This program is published under a MIT license
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#define SWAP_POINTERS(x, y) { void *p = x; x = y; y = p; }

//IP constant definitions
#define IPv4_VERSION 4
#define IPv4_ADDR_SIZE 4
#define IPv4_ADDR_STR_LENGTH 16
#define IPv4_HEADER_SIZE 20
#define IPv4_PAYLOAD_LEN ETH_DATA_LEN - IPv4_HEADER_SIZE
#define DEFAULT_TTL 64

//UDP constant definitions
#define UDP_HEADER_SIZE 8

#ifdef CPU_COUNTERS
#include <cpuid.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <asm/msr-index.h>

unsigned int sys_cstates_usage;
int sys_cstates_num;
unsigned int skip_c0;
unsigned int skip_c1;
unsigned int do_nhm_cstates;
unsigned int do_snb_cstates;
unsigned int do_slm_cstates;
unsigned int use_c1_residency_msr;
unsigned int has_aperf;
unsigned int has_epb;
unsigned int genuine_intel;
unsigned int has_invariant_tsc;
unsigned int do_rapl;
unsigned int do_dts;
unsigned int do_ptm;
char output_buffer[1024], *outp;
double rapl_power_units, rapl_energy_units, rapl_time_units;
double rapl_joule_counter_range;

#define RAPL_PKG		(1 << 0)
					/* 0x610 MSR_PKG_POWER_LIMIT */
					/* 0x611 MSR_PKG_ENERGY_STATUS */
#define RAPL_PKG_PERF_STATUS	(1 << 1)
					/* 0x613 MSR_PKG_PERF_STATUS */
#define RAPL_PKG_POWER_INFO	(1 << 2)
					/* 0x614 MSR_PKG_POWER_INFO */

#define RAPL_DRAM		(1 << 3)
					/* 0x618 MSR_DRAM_POWER_LIMIT */
					/* 0x619 MSR_DRAM_ENERGY_STATUS */
					/* 0x61c MSR_DRAM_POWER_INFO */
#define RAPL_DRAM_PERF_STATUS	(1 << 4)
					/* 0x61b MSR_DRAM_PERF_STATUS */

#define RAPL_CORES		(1 << 5)
					/* 0x638 MSR_PP0_POWER_LIMIT */
					/* 0x639 MSR_PP0_ENERGY_STATUS */
#define RAPL_CORE_POLICY	(1 << 6)
					/* 0x63a MSR_PP0_POLICY */


#define RAPL_GFX		(1 << 7)
					/* 0x640 MSR_PP1_POWER_LIMIT */
					/* 0x641 MSR_PP1_ENERGY_STATUS */
					/* 0x642 MSR_PP1_POLICY */

int aperf_mperf_unstable;
char *progname;

cpu_set_t cpu_affinity_set;

struct thread_data {
	unsigned long long tsc;
	unsigned long long aperf;
	unsigned long long mperf;
	unsigned long long c1;
	unsigned int cpu_id;
} thread[2];

struct core_data {
	unsigned long long c3;
	unsigned long long c6;
	unsigned long long c7;
} core[2];

struct pkg_data {
	unsigned int energy_pkg;	/* MSR_PKG_ENERGY_STATUS */

} package[2];

#define COUNTERS_0 &thread[0], &core[0], &package[0]
#define COUNTERS_1 &thread[1], &core[1], &package[1]

struct timeval tv[2], tv_delta;

void initialize_counters();
void finalize_counters();
void turbostat_init();
void sig_handler(int sig) {
	finalize_counters();
	exit(-1);
}
#endif

enum verbose { ERROR, WARN, DEBUG };

struct parsed_options {
	unsigned long long 	n;
	unsigned int		size;
	unsigned int		latency;
	unsigned int		fps;
	char			*iface;
	unsigned char		dstmac[6];
	char 			*dstip;
	char 			*srcip;
	unsigned short 		dstport;
	unsigned short 		srcport;
	char			*append;
	int 			verbose;
	int			transmit;
	int			listen;
	int			cpu_counters;
};

struct parsed_options options;

struct socket {
	int			fd;
	struct sockaddr_in	src, dst;
	struct sockaddr_ll	raw_dst;
	struct sockaddr 	*dev;
	socklen_t		dev_len;
};

struct timing {
	int			timer_fd;
	unsigned int 		frames_per_tick;
	int			ep_fd;
	struct epoll_event 	evs;
};

void parse_options(int argc, char *argv[]);
void init_udp_socket(struct socket *sock);
void init_raw_socket(struct socket *sock);
char *get_payload();
void init_timing(struct timing *tm);
void print_packet_debuginfo(void *buffer, int size);

int main(int argc, char *argv[]) {
	int 			ret;
	unsigned long 		i;
	struct socket		sock;
	struct timing		tm;
	char			*payload = NULL;
	uint64_t 		consume;
	char 			buffer[1500];

	parse_options(argc, argv);

#ifdef DMA_LATENCY
	int pm_qos_fd = open("/dev/cpu_dma_latency", O_RDWR);
	if (pm_qos_fd < 0 && options.verbose >= WARN) warn("open");
	else write(pm_qos_fd, &options.latency, sizeof(options.latency));
#endif

	// sender & receiver
	if (options.iface)
		init_raw_socket(&sock);
	else	init_udp_socket(&sock);

	// sender only
	if (!options.listen) {
		payload = get_payload();
		init_timing(&tm);
	}

#ifdef CPU_COUNTERS
	if (options.cpu_counters) {
		turbostat_init();
		initialize_counters();
		signal(SIGINT, sig_handler);
		signal(SIGKILL, sig_handler);
		signal(SIGTERM, sig_handler);
	}
#endif
	i = 0;
	// receiver
	if (options.listen) while (1) {
		ret = recv(sock.fd, (void *)buffer, sizeof(buffer), 0);
		if (ret < 0) err(1, "recv");
		if (options.verbose >= DEBUG)
			print_packet_debuginfo(buffer, ret);
		if (++i == options.n) goto clean; // :D
	}
	// sender
	else while(1) {
		// wait and consume timer data
		epoll_wait(tm.ep_fd, &tm.evs, 1, -1);
		ret = read(tm.timer_fd, &consume, sizeof(uint64_t));
		// send
		consume = consume * tm.frames_per_tick;
		if (ret > 0) for (int j=0; j<consume; j++) {
			if (options.transmit) {
				ret = sendto(sock.fd, (void *)payload, options.size, 0, sock.dev, sock.dev_len);
				if (ret < 0) err(1, "send");
			}
			if (options.verbose >= DEBUG)
				print_packet_debuginfo((void *)payload, options.transmit ? options.size : 0);
			if (++i == options.n) goto clean; // :DD
		}
	}

clean:
#ifdef CPU_COUNTERS
	if (options.cpu_counters) finalize_counters();
#endif
	if (!options.listen) free(payload);
	return 0;
}

void help(char *argv[]) {
    fprintf(stderr,
		"Usage: %s [options] [host] [port]\n"
		"\n"
		"Options:\n"
		"  -h            show help\n"
		"  -v            verbose\n"
		"  -l            listen for incoming packets\n"
		"  -D            do not send packets\n"
#ifdef CPU_COUNTERS
		"  -C            activate CPU counters (must be root)\n"
#endif
#ifdef DMA_LATENCY
		"  -L <latency>  specify max latency                      default: 1000\n"
#endif
		"  -p <port>     specify source port to use\n"
		"  -n <pkts>     number of packets                        default: 0 (inf)\n"
		"  -s <size>     payload length                           default: 7\n"
		"  -f <fps>      frames per second                        default: 1\n"
		"  -a <str>      specify custom payload\n"
		"  -i <iface>    output interface (enables raw sockets)\n"
		"  -m <MAC>      specify custom dst MAC (only raw)        default: 00:11:22:33:44:55\n"
		"\n",
    argv[0]);
}

void parse_options(int argc, char *argv[]) {
	int c, h=0;

	options.verbose = 0;
	options.transmit = 1;
	options.listen = 0;
	options.cpu_counters = 0;
	options.n = 0;
	options.size = 7;
	options.latency = 1000;
	options.fps = 1;
	options.srcport = 0;
	options.iface = NULL;
	options.srcip = NULL;
	options.dstmac[0] = 0x00;
	options.dstmac[1] = 0x11;
	options.dstmac[2] = 0x22;
	options.dstmac[3] = 0x33;
	options.dstmac[4] = 0x44;
	options.dstmac[5] = 0x55;

	while (-1 != (c = getopt(argc, argv, "hvlDCL:n:s:f:p:a:i:m:"))) {
		switch (c) {
		case 'h': //help
			h = 1;
			break;
		case 'v': //verbose
			options.verbose++;
			break;
		case 'l': //listen
			options.listen = 1;
			break;
		case 'D': //do not transmit
			options.transmit = 0;
			break;
#ifdef CPU_COUNTERS
		case 'C': //activate CPU counters
			options.cpu_counters = 1;
			break;
#endif
#ifdef DMA_LATENCY
		case 'L': //max latency
			options.latency = strtoul(optarg, NULL, 0);
			break;
#endif
		case 'n': //number of packets
			options.n = strtoul(optarg, NULL, 0);
			break;
		case 's': //payload length
			options.size = strtoul(optarg, NULL, 0);
			break;
		case 'f': //fps
			options.fps = strtoul(optarg, NULL, 0);
			if (!options.fps) options.fps = 1;
			break;
		case 'p': //source port
			options.srcport = (unsigned short)atoi(optarg);
			if (options.srcport < 0) options.srcport = 0;
			break;
		case 'a': //append
			options.append = optarg;
			break;
		case 'i': //iface name (enables raw sockets)
			options.iface = optarg;
			break;
		case 'm': //mac address (raw sockets)
			sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			       &options.dstmac[0], &options.dstmac[1], &options.dstmac[2],
			       &options.dstmac[3], &options.dstmac[4], &options.dstmac[5]);
			break;
		}
	}
	if (h) {
		help(argv);
		exit(-1);
	}
	if (options.listen) {
		if (optind+1 != argc) errx(1, "You MUST specify a port to listen");
		options.srcport = (unsigned short)atoi(argv[optind++]);
		if (options.srcport < 0) options.srcport = 31337;
	} else {
		if (optind+2 != argc) errx(1, "You MUST specify IP and destination port");
		options.dstip = argv[optind++];
		options.dstport = (unsigned short)atoi(argv[optind++]);
	}
}

void init_udp_socket(struct socket *sock) {
	int ret;

	sock->src.sin_family = AF_INET;
	sock->src.sin_port = htons(options.srcport);
	sock->src.sin_addr.s_addr = INADDR_ANY;
	if (!options.listen) {
		sock->dst.sin_family = AF_INET;
		sock->dst.sin_port = htons(options.dstport);
		ret = inet_aton(options.dstip, (struct in_addr *)&sock->dst.sin_addr.s_addr);
		if (ret < 0) err(1, "inet_aton");
		sock->dev = (struct sockaddr *)&sock->dst;
		sock->dev_len = sizeof(sock->dst);
	}

	sock->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock->fd < 0) err(1, "socket");

	ret = bind(sock->fd, (struct sockaddr *)&sock->src, sizeof(sock->src));
	if (ret < 0) err(1, "bind");

	int broadcast = 1;
	ret = setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
	if (ret < 0) err(1, "setsockopt");
}

void init_raw_socket(struct socket *sock) {
	options.size += IPv4_HEADER_SIZE + UDP_HEADER_SIZE;

	memset(&sock->raw_dst, 0, sizeof(sock->raw_dst));
	if ((sock->raw_dst.sll_ifindex = if_nametoindex(options.iface)) < 0)
		err(1, "if_nametoindex");
	sock->raw_dst.sll_family = AF_PACKET;
	sock->raw_dst.sll_protocol = htons(ETH_P_IP);
	memcpy(sock->raw_dst.sll_addr, options.dstmac, ETH_ALEN);
	sock->raw_dst.sll_halen = ETH_ALEN;
	sock->dev = (struct sockaddr *)&sock->raw_dst;
	sock->dev_len = sizeof(sock->raw_dst);

	sock->fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sock->fd < 0) err(1, "socket");
}

char *get_payload() {
	int 		ret, i = 0;
	struct ip	iphdr;
	struct udphdr	udphdr;
	char		*def_pay="payload";
	char		*seed = def_pay;
	char		*payload = NULL;

	payload = (char *)malloc(options.size);
	if (!payload) err(1, "malloc");

	if (options.iface) {
		i = IPv4_HEADER_SIZE + UDP_HEADER_SIZE;

		// IP
		iphdr.ip_hl = IPv4_HEADER_SIZE / sizeof(uint32_t);
		iphdr.ip_v = IPv4_VERSION;
		iphdr.ip_tos = 0;
		iphdr.ip_len = htons(options.size);
		iphdr.ip_id = htons(0);
		iphdr.ip_off = 0;
		iphdr.ip_ttl = DEFAULT_TTL;
		iphdr.ip_p = IPPROTO_UDP;
		if (options.srcip)
			ret = inet_pton(AF_INET, options.srcip, &(iphdr.ip_src));
		else    ret = inet_pton(AF_INET, "1.2.3.4", &(iphdr.ip_src));
		if (ret < 1) err(1, "inet_pton");
		ret = inet_pton(AF_INET, options.dstip, &(iphdr.ip_dst));
		if (ret < 1) err(1, "inet_pton");
		iphdr.ip_sum = 0;
		memcpy(payload, &iphdr, IPv4_HEADER_SIZE);

		// UDP
		if (options.srcport)
			udphdr.source = htons(options.srcport);
		else	udphdr.source = htons(5000);
		udphdr.dest = htons(options.dstport);
		udphdr.len = htons(options.size - IPv4_HEADER_SIZE);
		udphdr.check = 0;
		memcpy(payload + IPv4_HEADER_SIZE, &udphdr, UDP_HEADER_SIZE);
	}

	// data
	if (options.append) seed = options.append;
	for (i=i; i<options.size; i++)
		payload[i] = seed[i%strlen(seed)];

	return payload;
}

void init_timing(struct timing *tm) {
	int 			ret;
	unsigned long 		sec, nsec;
	struct timespec		res;
	struct itimerspec	timerSpec, oldSpec;
	struct epoll_event	ev;

	sec = 1/options.fps;
	nsec = 1e9/options.fps - sec*1e9;
	tm->frames_per_tick = 0;
	if (nsec) {
		ret = clock_getres(CLOCK_MONOTONIC, &res);
		if (ret < 0) err(1, "clock_getres");
		tm->frames_per_tick = res.tv_nsec/(double)nsec;
	}
	if (!tm->frames_per_tick) tm->frames_per_tick = 1;

	timerSpec.it_value.tv_sec = sec;
	timerSpec.it_value.tv_nsec = nsec;
	timerSpec.it_interval.tv_sec = sec;
	timerSpec.it_interval.tv_nsec = nsec;

	tm->timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tm->timer_fd < 0) err(1, "timerfd_create");

	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	tm->ep_fd = epoll_create1(0);
	if (tm->ep_fd < 0) err(1, "epoll_create1");
	ret = epoll_ctl(tm->ep_fd, EPOLL_CTL_ADD, tm->timer_fd, &ev);
	if (ret < 0) err(1, "epoll_ctl");

	ret = timerfd_settime(tm->timer_fd, 0, &timerSpec, &oldSpec);
	if (ret < 0) err(1, "timerfd_settime");
}

void print_packet_debuginfo(void *buffer, int size) {
	static struct timeval tv[2], tv_delta;
	static struct timeval *tv_last = &tv[0];
	static struct timeval *tv_cur = &tv[1];

	if (!buffer || size < 0) return;

	gettimeofday(tv_cur, (struct timezone *)NULL);
	if (timerisset(tv_last))
		timersub(tv_cur, tv_last, &tv_delta);
	printf("%ld.%06ld %ld.%06ld [%i] ",
		tv_cur->tv_sec, tv_cur->tv_usec,
		tv_delta.tv_sec, tv_delta.tv_usec, size
	      );
	fflush(stdout);
	write(1, (void *)buffer, size);
	printf("\n");
	SWAP_POINTERS(tv_cur, tv_last);
}

#ifdef CPU_COUNTERS
int get_msr(int cpu, off_t offset, unsigned long long *msr)
{
	ssize_t retval;
	char pathname[32];
	int fd;

	sprintf(pathname, "/dev/cpu/%d/msr", cpu);
	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -1;

	retval = pread(fd, msr, sizeof *msr, offset);
	close(fd);

	if (retval != sizeof *msr) {
		fprintf(stderr, "%s offset 0x%llx read failed\n", pathname, (unsigned long long)offset);
		return -1;
	}

	return 0;
}

static unsigned long long rdtsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return low | ((unsigned long long)high) << 32;
}

/*int cpu_migrate(int cpu)
{
	CPU_ZERO_S(1, &cpu_affinity_set);
	CPU_SET_S(cpu, 1, &cpu_affinity_set);
	if (sched_setaffinity(0, 1, &cpu_affinity_set) == -1)
		return -1;
	else
		return 0;
}*/

/*
 * get_counters(...)
 * migrate to cpu
 * acquire and record local counters for that cpu
 */
int get_counters(struct thread_data *t, struct core_data *c, struct pkg_data *p)
{
	int cpu = t->cpu_id;
	unsigned long long msr;

	/*if (cpu_migrate(cpu)) {
		fprintf(stderr, "Could not migrate to CPU %d\n", cpu);
		return -1;
	}*/

	t->tsc = rdtsc();	/* we are running on local CPU of interest */

	if (has_aperf) {
		if (get_msr(cpu, MSR_IA32_APERF, &t->aperf))
			return -3;
		if (get_msr(cpu, MSR_IA32_MPERF, &t->mperf))
			return -4;
	}

	if (use_c1_residency_msr) {
		if (get_msr(cpu, MSR_CORE_C1_RES, &t->c1))
			return -6;
	}

	if (do_nhm_cstates && !do_slm_cstates) {
		if (get_msr(cpu, MSR_CORE_C3_RESIDENCY, &c->c3))
			return -6;
	}

	if (do_nhm_cstates) {
		if (get_msr(cpu, MSR_CORE_C6_RESIDENCY, &c->c6))
			return -7;
	}

	if (do_snb_cstates)
		if (get_msr(cpu, MSR_CORE_C7_RESIDENCY, &c->c7))
			return -8;

	if (do_rapl & RAPL_PKG) {
		if (get_msr(cpu, MSR_PKG_ENERGY_STATUS, &msr))
			return -13;
		p->energy_pkg = msr & 0xFFFFFFFF;
	}
	return 0;
}

void
delta_core(struct core_data *new, struct core_data *old)
{
	old->c3 = new->c3 - old->c3;
	old->c6 = new->c6 - old->c6;
	old->c7 = new->c7 - old->c7;
}

/*
 * old = new - old
 */
void
delta_thread(struct thread_data *new, struct thread_data *old,
	struct core_data *core_delta)
{
	old->tsc = new->tsc - old->tsc;

	/* check for TSC < 1 Mcycles over interval */
	if (old->tsc < (1000 * 1000))
		errx(-3, "Insanely slow TSC rate, TSC stops in idle?\n"
		     "You can disable all c-states by booting with \"idle=poll\"\n"
		     "or just the deep ones with \"processor.max_cstate=1\"");

	old->c1 = new->c1 - old->c1;

	if ((new->aperf > old->aperf) && (new->mperf > old->mperf)) {
		old->aperf = new->aperf - old->aperf;
		old->mperf = new->mperf - old->mperf;
	} else {

		if (!aperf_mperf_unstable) {
			fprintf(stderr, "%s: APERF or MPERF went backwards *\n", progname);
			fprintf(stderr, "* Frequency results do not cover entire interval *\n");
			fprintf(stderr, "* fix this by running Linux-2.6.30 or later *\n");

			aperf_mperf_unstable = 1;
		}
		/*
		 * mperf delta is likely a huge "positive" number
		 * can not use it for calculating c0 time
		 */
		skip_c0 = 1;
		skip_c1 = 1;
	}


	if (use_c1_residency_msr) {
		/*
		 * Some models have a dedicated C1 residency MSR,
		 * which should be more accurate than the derivation below.
		 */
	} else {
		/*
		 * As counter collection is not atomic,
		 * it is possible for mperf's non-halted cycles + idle states
		 * to exceed TSC's all cycles: show c1 = 0% in that case.
		 */
		if ((old->mperf + core_delta->c3 + core_delta->c6 + core_delta->c7) > old->tsc)
			old->c1 = 0;
		else {
			/* normal case, derive c1 */
			old->c1 = old->tsc - old->mperf - core_delta->c3
				- core_delta->c6 - core_delta->c7;
		}
	}

	if (old->mperf == 0) {
		if (options.verbose >= DEBUG) fprintf(stderr, "cpu%d MPERF 0!\n", old->cpu_id);
		old->mperf = 1;	/* divide by 0 protection */
	}
}

#define DELTA_WRAP32(new, old)			\
	if (new > old) {			\
		old = new - old;		\
	} else {				\
		old = 0x100000000 + new - old;	\
	}

void
delta_package(struct pkg_data *new, struct pkg_data *old)
{
	DELTA_WRAP32(new->energy_pkg, old->energy_pkg);
}

int delta_cpu(struct thread_data *t, struct core_data *c,
	struct pkg_data *p, struct thread_data *t2,
	struct core_data *c2, struct pkg_data *p2)
{
	delta_core(c, c2);
	delta_thread(t, t2, c2);
	delta_package(p, p2);

	return 0;
}

void initialize_counters() {
	int retval;
	FILE *fd;
	DIR *dirp;
	struct dirent *dp;
	unsigned int usage;
	char name[100];

	sys_cstates_usage = 0;
	sys_cstates_num = -2;
	if ((dirp = opendir("/sys/devices/system/cpu/cpu0/cpuidle/"))) {
		while ((dp = readdir(dirp)) != NULL) sys_cstates_num++;
		closedir(dirp);
	}

	for (int i=0; i<sys_cstates_num; i++) {
		sprintf(name, "/sys/devices/system/cpu/cpu0/cpuidle/state%i/usage", i);
                if ((fd = fopen(name, "r"))) {
                        fscanf(fd, "%u", &(usage));
			sys_cstates_usage -= usage;
                        fclose(fd);
                }
	}

	retval = get_counters(COUNTERS_0);
	if (retval < -1) {
		exit(retval);
	}
	gettimeofday(&tv[0], (struct timezone *)NULL);
}

int format_counters(struct thread_data *t, struct core_data *c, struct pkg_data *p) {
	double interval_float;
	char *fmt8;

	outp = output_buffer;

	interval_float = tv_delta.tv_sec + tv_delta.tv_usec/1000000.0;
	/*
 	 * If measurement interval exceeds minimum RAPL Joule Counter range,
 	 * indicate that results are suspect by printing "**" in fraction place.
 	 */
	if (interval_float < rapl_joule_counter_range)
		fmt8 = "%.3f ";
	else
		fmt8 = "** ";

	if (do_rapl & RAPL_PKG) {
		outp += sprintf(outp, fmt8, p->energy_pkg * rapl_energy_units / interval_float);
		outp += sprintf(outp, "%.6f ", interval_float);
	}

	if (!skip_c0)
		outp += sprintf(outp, "%.4f ", t->mperf/(double)t->tsc);
	else
		outp += sprintf(outp, "** ");

	if (do_nhm_cstates) {
		if (!skip_c1)
			outp += sprintf(outp, "%.4f ", t->c1/(double)t->tsc);
		else
			outp += sprintf(outp, "** ");
	}
	if (do_nhm_cstates && !do_slm_cstates)
		outp += sprintf(outp, "%.4f ", c->c3/(double)t->tsc);
	if (do_nhm_cstates)
		outp += sprintf(outp, "%.4f ", c->c6/(double)t->tsc);
	if (do_snb_cstates)
		outp += sprintf(outp, "%.4f ", c->c7/(double)t->tsc);

	if (sys_cstates_num)
		outp += sprintf(outp, "%.2f ", sys_cstates_usage / interval_float);

	outp += sprintf(outp, "\n");

	return 0;
}

void finalize_counters() {
	int retval;
	FILE *fd;
	unsigned int usage;
	char name[100];

	for (int i=0; i<sys_cstates_num; i++) {
		sprintf(name, "/sys/devices/system/cpu/cpu0/cpuidle/state%i/usage", i);
                if ((fd = fopen(name, "r"))) {
                        fscanf(fd, "%u", &(usage));
			sys_cstates_usage += usage;
                        fclose(fd);
                }
	}

	retval = get_counters(COUNTERS_1);
	if (retval < -1) {
		exit(retval);
	}
	gettimeofday(&tv[1], (struct timezone *)NULL);

	timersub(&tv[1], &tv[0], &tv_delta);
	delta_cpu(COUNTERS_1, COUNTERS_0);
	format_counters(COUNTERS_0);
	fputs(output_buffer, stdout);

	/*
	c0 = time_factor;
	for (int i=0; i<stats.n; i++)
		c0 -= stats.cstate[i].time;
	printf("%.4f ", c0 / time_factor);
	for (int i=0; i<stats.n; i++)
		printf("%.4f %.4f ", stats.cstate[i].time / time_factor, stats.cstate[i].usage / (time_factor/1000000.0));
	printf("\n");*/
}

#define	RAPL_POWER_GRANULARITY	0x7FFF	/* 15 bit power granularity */

double get_tdp(int model)
{
	unsigned long long msr;

	if (do_rapl & RAPL_PKG_POWER_INFO)
		if (!get_msr(0, MSR_PKG_POWER_INFO, &msr))
			return ((msr >> 0) & RAPL_POWER_GRANULARITY) * rapl_power_units;

	switch (model) {
	case 0x37:
	case 0x4D:
		return 30.0;
	default:
		return 135.0;
	}
}

/*
 * rapl_probe()
 *
 * sets do_rapl, rapl_power_units, rapl_energy_units, rapl_time_units
 */
void rapl_probe(unsigned int family, unsigned int model)
{
	unsigned long long msr;
	unsigned int time_unit;
	double tdp;

	if (!genuine_intel)
		return;

	if (family != 6)
		return;

	switch (model) {
	case 0x2A:
	case 0x3A:
	case 0x3C:	/* HSW */
	case 0x45:	/* HSW */
	case 0x46:	/* HSW */
	case 0x3D:	/* BDW */
		do_rapl = RAPL_PKG | RAPL_CORES | RAPL_CORE_POLICY | RAPL_GFX | RAPL_PKG_POWER_INFO;
		break;
	case 0x3F:	/* HSX */
	case 0x4F:	/* BDX */
	case 0x56:	/* BDX-DE */
		do_rapl = RAPL_PKG | RAPL_DRAM | RAPL_DRAM_PERF_STATUS | RAPL_PKG_PERF_STATUS | RAPL_PKG_POWER_INFO;
		break;
	case 0x2D:
	case 0x3E:
		do_rapl = RAPL_PKG | RAPL_CORES | RAPL_CORE_POLICY | RAPL_DRAM | RAPL_PKG_PERF_STATUS | RAPL_DRAM_PERF_STATUS | RAPL_PKG_POWER_INFO;
		break;
	case 0x37:	/* BYT */
	case 0x4D:	/* AVN */
		do_rapl = RAPL_PKG | RAPL_CORES ;
		break;
	default:
		return;
	}

	/* units on package 0, verify later other packages match */
	if (get_msr(0, MSR_RAPL_POWER_UNIT, &msr))
		return;

	rapl_power_units = 1.0 / (1 << (msr & 0xF));
	if (model == 0x37)
		rapl_energy_units = 1.0 * (1 << (msr >> 8 & 0x1F)) / 1000000;
	else
		rapl_energy_units = 1.0 / (1 << (msr >> 8 & 0x1F));

	time_unit = msr >> 16 & 0xF;
	if (time_unit == 0)
		time_unit = 0xA;

	rapl_time_units = 1.0 / (1 << (time_unit));

	tdp = get_tdp(model);

	rapl_joule_counter_range = 0xFFFFFFFF * rapl_energy_units / tdp;
	if (options.verbose >= DEBUG)
		fprintf(stderr, "RAPL: %.0f sec. Joule Counter Range, at %.0f Watts\n", rapl_joule_counter_range, tdp);

	return;
}

int is_snb(unsigned int family, unsigned int model)
{
	if (!genuine_intel)
		return 0;

	switch (model) {
	case 0x2A:
	case 0x2D:
	case 0x3A:	/* IVB */
	case 0x3E:	/* IVB Xeon */
	case 0x3C:	/* HSW */
	case 0x3F:	/* HSW */
	case 0x45:	/* HSW */
	case 0x46:	/* HSW */
	case 0x3D:	/* BDW */
	case 0x4F:	/* BDX */
	case 0x56:	/* BDX-DE */
		return 1;
	}
	return 0;
}

int is_slm(unsigned int family, unsigned int model)
{
	if (!genuine_intel)
		return 0;
	switch (model) {
	case 0x37:	/* BYT */
	case 0x4D:	/* AVN */
		return 1;
	}
	return 0;
}

void check_cpuid()
{
	unsigned int eax, ebx, ecx, edx, max_level;
	unsigned int fms=0, family, model, stepping;

	eax = ebx = ecx = edx = 0;

	__get_cpuid(0, &max_level, &ebx, &ecx, &edx);

	if (ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e)
		genuine_intel = 1;

	if (options.verbose >= DEBUG)
		fprintf(stderr, "CPUID(0): %.4s%.4s%.4s ",
			(char *)&ebx, (char *)&edx, (char *)&ecx);

	__get_cpuid(1, &fms, &ebx, &ecx, &edx);
	family = (fms >> 8) & 0xf;
	model = (fms >> 4) & 0xf;
	stepping = fms & 0xf;
	if (family == 6 || family == 0xf)
		model += ((fms >> 16) & 0xf) << 4;

	if (options.verbose >= DEBUG)
		fprintf(stderr, "%d CPUID levels; family:model:stepping 0x%x:%x:%x (%d:%d:%d)\n",
			max_level, family, model, stepping, family, model, stepping);

	if (!(edx & (1 << 5)))
		errx(1, "CPUID: no MSR");

	/*
	 * check max extended function levels of CPUID.
	 * This is needed to check for invariant TSC.
	 * This check is valid for both Intel and AMD.
	 */
	ebx = ecx = edx = 0;
	__get_cpuid(0x80000000, &max_level, &ebx, &ecx, &edx);

	if (max_level < 0x80000007)
		errx(1, "CPUID: no invariant TSC (max_level 0x%x)", max_level);

	/*
	 * Non-Stop TSC is advertised by CPUID.EAX=0x80000007: EDX.bit8
	 * this check is valid for both Intel and AMD
	 */
	__get_cpuid(0x80000007, &eax, &ebx, &ecx, &edx);
	has_invariant_tsc = edx & (1 << 8);

	if (!has_invariant_tsc)
		errx(1, "No invariant TSC");

	/*
	 * APERF/MPERF is advertised by CPUID.EAX=0x6: ECX.bit0
	 * this check is valid for both Intel and AMD
	 */

	__get_cpuid(0x6, &eax, &ebx, &ecx, &edx);
	has_aperf = ecx & (1 << 0);
	do_dts = eax & (1 << 0);
	do_ptm = eax & (1 << 6);
	has_epb = ecx & (1 << 3);

	if (options.verbose >= DEBUG)
		fprintf(stderr, "CPUID(6): %s%s%s%s\n",
			has_aperf ? "APERF" : "No APERF!",
			do_dts ? ", DTS" : "",
			do_ptm ? ", PTM": "",
			has_epb ? ", EPB": "");

	if (!has_aperf)
		errx(-1, "No APERF");

	do_nhm_cstates = genuine_intel;	/* all Intel w/ non-stop TSC have NHM counters */
	do_snb_cstates = is_snb(family, model);
	do_slm_cstates = is_slm(family, model);

	rapl_probe(family, model);

	return;
}

void check_dev_msr()
{
	struct stat sb;

	if (stat("/dev/cpu/0/msr", &sb))
		err(-5, "no /dev/cpu/0/msr\n"
		    "Try \"# modprobe msr\"");
}

void check_super_user()
{
	if (getuid() != 0)
		errx(-6, "must be root");
}

void turbostat_init()
{
	check_cpuid();

	check_dev_msr();
	check_super_user();
}
#endif
