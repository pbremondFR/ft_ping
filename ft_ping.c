#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>
#include <error.h>
#include <stdatomic.h>
#include <math.h>
#include <string.h>
#include <errno.h>

#include "ft_ping.h"

struct ft_ping_state	g_state = {
	.num_to_send = -1,
	.verbose = false,
	.ttl = 112,
	.interval = 1,
	.sockfd = 0,
	.sockaddr = {},
	.pid = 0,
	.ping_tgt_name = NULL,
	.ping_tgt_addr = {},
	.started_at = {},
	.sent = 0,
	.received = 0,
};

struct icmphdr	get_icmp_echo_header(uint16_t id, uint16_t seq)
{
	return (struct icmphdr){
		.type = ICMP_ECHO,
		.code = 0,
		.un.echo = {
			.id = id,
			.sequence = seq
		}
	};
}

static long parse_numerical_flag(char *arg)
{
	char *endptr = NULL;
	if (!arg)
		return LONG_MIN;
	long res = strtol(arg, &endptr, 10);
	if (!endptr || *endptr != 0)
		return LONG_MIN;
	else
		return res;
}

static void	parse_options(int argc, char *const *argv)
{
	int	opt = 0;

	while ((opt = getopt(argc, argv, "vt:c:i:")) != -1)
	{
		switch (opt)
		{
		case 'v':
			g_state.verbose = true;
			break;
		case 't':
		{
			long ttl = parse_numerical_flag(optarg);
			if (ttl <= 0 || ttl > UINT32_MAX)
				error(1, 0, "invalid argument: '%ld': out of range: 0 <= value <= 255", ttl);
			g_state.ttl = (uint32_t)ttl;
			break;
		}
		case 'c':
		{
			long count = parse_numerical_flag(optarg);
			if (count <= 0 || count >= SIG_ATOMIC_MAX)
				error(1, 0, "invalid argument: '%ld': out of range: 0 <= value <= %d", count, SIG_ATOMIC_MAX);
			g_state.num_to_send = (sig_atomic_t)count;
			break;
		}
		case 'i':
		{
			long interval = parse_numerical_flag(optarg);
			if (interval <= 0 || interval >= SIG_ATOMIC_MAX)
				error(1, 0, "invalid argument: '%ld': out of range: 0 <= value <= %d", interval, UINT_MAX);
			g_state.interval = (unsigned int)interval;
			break;
		}
		case '?':
			exit(1);
			break;
		default:
			error(1, 0, "unknown option");
			break;
		}
	}

}

int	main(int argc, char *const *argv)
{
	parse_options(argc, argv);
	printf("num to send: %d, ttl: %d, verbose: %d, interval: %d\n", g_state.num_to_send, g_state.ttl, g_state.verbose, g_state.interval);

	if (optind == argc)
	{
		error(1, 0, "missing argument");
	}
	for (int i = optind; i < argc; ++i)
	{
		printf("> %s\n", argv[i]);
	}

	struct addrinfo hints = {};
	struct addrinfo *tgtinfo;
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

	int result = getaddrinfo(argv[optind], NULL, &hints, &tgtinfo);
	if (result == 0)
	{
		for (struct addrinfo *head = tgtinfo; head; head = head->ai_next)
		{
			printf("ai_flags:     %d\n", 	head->ai_flags);
			printf("ai_family:    %d\n", 	head->ai_family);
			printf("ai_socktype:  %d\n", 	head->ai_socktype);
			printf("ai_protocol:  %d\n", 	head->ai_protocol);
			printf("ai_addrlen:   %u\n", 	head->ai_addrlen);
			printf("ai_addr:      %p\n", 	head->ai_addr);
			printf("ai_canonname: %s\n",	head->ai_canonname);
			printf("ai_next:      %p\n", 	head->ai_next);

			struct sockaddr_in *ipv4 = (struct sockaddr_in*)head->ai_addr;
			printf("IP is %s\n", inet_ntoa(ipv4->sin_addr));
			puts("========================\n");
		}
	}
	else
		error(2, result, "getaddrinfo call failed");

	struct sockaddr_in *ipv4 = (struct sockaddr_in*)tgtinfo->ai_addr;

	g_state.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (g_state.sockfd == -1)
		error(2, errno, "failed to create socket");

	// if (connect(g_state.sockfd, &g_state.sockaddr, INET_ADDRSTRLEN) != 0)
	// 	error(2, errno, "error trying to connect to socket");


	g_state.pid = getpid();
	g_state.sockaddr = *(struct sockaddr*)ipv4;
	g_state.ping_tgt_addr = ipv4->sin_addr;
	g_state.ping_tgt_name = strdup(tgtinfo->ai_canonname);
	gettimeofday(&g_state.started_at, NULL);

	signal(SIGALRM, sigalrm_handler);
	signal(SIGINT, finish_ping);

	// TODO: start ping
	char ip_str_buf[3 * 4 + 4];
	inet_ntop(AF_INET, &g_state.ping_tgt_addr, ip_str_buf, sizeof(ip_str_buf));
	// TODO: Check if we really need 56 bytes?
	printf("PING %s (%s): 56 data bytes\n", g_state.ping_tgt_name, ip_str_buf);

	alarm(g_state.interval);

	while (true) ;
	finish_ping();
}

// Thank you RFC1071 for giving me the algorithm
uint16_t	get_inet_checksum(void *addr, size_t count)
{
	/* Compute Internet Checksum for "count" bytes
	*         beginning at location "addr".
	*/
	uint32_t	sum = 0;
	uint16_t	*data = (uint16_t*)addr;

	while( count > 1 )  {
		/*  This is the inner loop */
			sum += * data++;
			count -= 2;
	}

		/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

		/*  Add left-over byte, if any */
	if( count > 0 )
			sum += * (uint8_t *) data;

	return ~sum;
}

void	send_ping()
{
	unsigned char	buf[64] = {0};
	// size_t			packet_len = sizeof(struct icmp) + sizeof(struct timeval);
	size_t			packet_len = 56;

	struct icmp *icmp_packet = (struct icmp*)buf;
	icmp_packet->icmp_type = ICMP_ECHO;
	icmp_packet->icmp_code = 0;
	icmp_packet->icmp_id = g_state.pid;
	icmp_packet->icmp_seq = g_state.sent++;
	gettimeofday((struct timeval*)icmp_packet->icmp_data, NULL);
	// TODO: Calculate checksum
	icmp_packet->icmp_cksum = 0;
	uint16_t checksum = get_inet_checksum(buf, packet_len);
	icmp_packet->icmp_cksum = checksum;
	sendto(g_state.sockfd, buf, packet_len, 0, &g_state.sockaddr, INET_ADDRSTRLEN);
}

void	sigalrm_handler()
{
	// At least on this platform, sig_atomic_t is not actually atomic and
	// doesn't need atomic fetch operations?
	// So atomic_fetch_sub(&g_state.num_to_send, -1) doesn't work
	if (g_state.num_to_send == -1 || g_state.num_to_send-- > 0)
	{
		// TODO: Send data...
		send_ping();
		alarm(g_state.interval);
	}
	else if (g_state.num_to_send <= 0)
	{
		finish_ping();
	}
}

void	finish_ping()
{
	// TODO: This is where ping stops
	printf("--- %s ping statistics ---\n", g_state.ping_tgt_name);

	float packet_loss = (float)g_state.received / g_state.sent;
	packet_loss = isnan(packet_loss) ? 0.0f : packet_loss;
	struct timeval now = {}, elapsed = {};
	gettimeofday(&now, NULL);
	timersub(&now, &g_state.started_at, &elapsed);
	double seconds_elapsed = elapsed.tv_sec + ((double)elapsed.tv_usec / 1e9);
	printf("%u packets transmitted, %u received, %.0f%% packet loss, time %.0fms\n",
		g_state.sent, g_state.received, packet_loss * 100, seconds_elapsed * 1000);

	free(g_state.ping_tgt_name);
	exit(0);
}
