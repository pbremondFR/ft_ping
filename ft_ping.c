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

	struct addrinfo hints = {};
	struct addrinfo *tgtinfo;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW; // XXX: 0 of SOCK_RAW?
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
		error(2, 0, "unknown host: %s", gai_strerror(result));

	struct sockaddr_in *ipv4 = (struct sockaddr_in*)tgtinfo->ai_addr;

	g_state.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (g_state.sockfd == -1)
		error(2, errno, "failed to create socket");
	setsockopt(g_state.sockfd, SOL_IP, IP_TTL, &g_state.ttl, sizeof(g_state.ttl));

	g_state.pid = getpid();
	g_state.sockaddr = *(struct sockaddr*)ipv4;
	g_state.ping_tgt_addr = ipv4->sin_addr;
	g_state.ping_tgt_name = strdup(tgtinfo->ai_canonname);

	freeaddrinfo(tgtinfo);
	signal(SIGALRM, sigalrm_handler);
	signal(SIGINT, finish_ping);

	char ip_str_buf[3 * 4 + 4];
	inet_ntop(AF_INET, &g_state.ping_tgt_addr, ip_str_buf, sizeof(ip_str_buf));
	printf("PING %s (%s): %ld data bytes, id %#06x = %d\n",
		g_state.ping_tgt_name, ip_str_buf, PACKET_LEN - sizeof(struct icmphdr), g_state.pid, g_state.pid);

	sigalrm_handler();
	// alarm(g_state.interval);

	// receive_loop();
	// while (g_state.num_to_send > 0)
	// 	;
	while (true)
		;
	// finish_ping();
}

void	receive_single(uint16_t sequence_num)
{
	char				hostname[256];
	char				recv_buf[256];
	char				ip_str[INET_ADDRSTRLEN] = {0};
	struct sockaddr		recv_sockaddr = {};
	socklen_t			recv_socklen = sizeof(recv_sockaddr);

	ssize_t received = recvfrom(g_state.sockfd, recv_buf, sizeof(recv_buf), 0,
		&recv_sockaddr, &recv_socklen);
	if (received < 0)
		error(3, errno, "recvfrom call failed");

	struct ip *ip = (struct ip*)recv_buf;
	if (ip->ip_p != IPPROTO_ICMP)
		return;
	// ip_hl: header length, number of 4-byte words in IP header.
	struct icmp *icmp = (struct icmp*)(recv_buf + (ip->ip_hl * 4));
	// printf("Infotype? %s, type %d\n", ICMP_INFOTYPE(icmp->icmp_type) ? "YES" : "no", icmp->icmp_type);

	if (icmp->icmp_id != (uint16_t)g_state.pid) {
		printf("fucked up PID: %d, mine is %d, getpid() is %d\n", icmp->icmp_id, g_state.pid, getpid());
		return;
	}

	if (icmp->icmp_type == ICMP_ECHOREPLY)
	{
		int gai_err;
		if ((gai_err = getnameinfo(&recv_sockaddr, recv_socklen, hostname, sizeof(hostname), NULL, 0, 0)) != EXIT_SUCCESS)
			error(3, 0, "getnameinfo() call failed: %s", gai_strerror(gai_err));

		if (icmp->icmp_seq != sequence_num)
			printf("FUCKED UP ICMP SEQUENCE\n");

		g_state.received++;
		printf("%zu bytes from %s: icmp_seq=%d, ttl=%d, time=%.03f ms\n",
			received - (ip->ip_hl * 4), hostname, icmp->icmp_seq, ip->ip_ttl, 0.0f);
	}
	else
	{
		printf("IP Hdr Dump:\n");
		printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");
	}
}

void	receive_loop()
{
	char				hostname[256];
	char				recv_buf[256];
	char				ip_str[INET_ADDRSTRLEN] = {0};
	struct sockaddr		recv_sockaddr = {};
	socklen_t			recv_socklen = sizeof(recv_sockaddr);

	while (true)
	{
		ssize_t received = recvfrom(g_state.sockfd, recv_buf, sizeof(recv_buf), 0,
			&recv_sockaddr, &recv_socklen);
		if (received < 0)
			error(3, errno, "recvfrom call failed");

		struct ip *ip = (struct ip*)recv_buf;
		if (ip->ip_p != IPPROTO_ICMP)
			continue;
		// ip_hl: header length, number of 4-byte words in IP header.
		struct icmp *icmp = (struct icmp*)(recv_buf + (ip->ip_hl * 4));
		printf("Infotype? %s, type %d\n", ICMP_INFOTYPE(icmp->icmp_type) ? "YES" : "no", icmp->icmp_type);

		if (icmp->icmp_id != (uint16_t)g_state.pid) {
			printf("fucked up PID: %d, mine is %d, getpid() is %d\n", icmp->icmp_id, g_state.pid, getpid());
			continue;
		}

		if (icmp->icmp_type == ICMP_ECHOREPLY)
		{
			int gai_err;
			if ((gai_err = getnameinfo(&recv_sockaddr, recv_socklen, hostname, sizeof(hostname), NULL, 0, 0)) != EXIT_SUCCESS)
				error(3, 0, "getnameinfo() call failed: %s", gai_strerror(gai_err));

			g_state.received++;
			printf("%zu bytes from %s: icmp_seq=%d, ttl=%d, time=%.03f ms\n",
				received - (ip->ip_hl * 4), hostname, icmp->icmp_seq, ip->ip_ttl, 0.0f);
		}
		else
		{
			printf("IP Hdr Dump:\n");
			printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");
		}
	}
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

void	send_ping(uint16_t sequence_num)
{
	const size_t	packet_len = PACKET_LEN;
	unsigned char	buf[PACKET_LEN] = {
		/* ICMP header: 8 bytes */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* ICMP data: struct timeval (16 bytes)... */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* ICMP data: ... This data pattern */
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
	};

	struct icmp *icmp_packet = (struct icmp*)buf;
	icmp_packet->icmp_type = ICMP_ECHO;
	icmp_packet->icmp_code = 0;
	icmp_packet->icmp_id = (uint16_t)g_state.pid;
	icmp_packet->icmp_seq = sequence_num;
	gettimeofday((struct timeval*)icmp_packet->icmp_data, NULL);
	icmp_packet->icmp_cksum = get_inet_checksum(buf, packet_len);
	sendto(g_state.sockfd, buf, packet_len, 0, &g_state.sockaddr, INET_ADDRSTRLEN);
}

void	sigalrm_handler()
{
	// At least on this platform, sig_atomic_t is not actually atomic and
	// doesn't need atomic fetch operations?
	// So atomic_fetch_sub(&g_state.num_to_send, -1) doesn't work
	if (g_state.num_to_send == -1 || g_state.num_to_send-- > 0)
	{
		uint16_t seq = g_state.sent++;
		send_ping(seq);
		alarm(g_state.interval);
		// g_state.num_to_send--;
		receive_single(seq);
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
	packet_loss = 1.0f - (isnan(packet_loss) ? 0.0f : packet_loss);
	printf("%u packets transmitted, %u received, %.0f%% packet loss\n",
		g_state.sent, g_state.received, packet_loss * 100);

	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
		0.0f, 0.0f, 0.0f, 0.0f);
	free(g_state.ping_tgt_name);
	close(g_state.sockfd);
	exit(0);
}
