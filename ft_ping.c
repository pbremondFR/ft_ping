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
	.rtt = {
		.data = NULL,
		.size = 0,
		.capacity = 0,
	},
};

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
	g_state.ping_tgt_name = argv[optind];
	g_state.rtt = (struct Vector){
		.data = malloc(8 * sizeof(float)),
		.size = 0,
		.capacity = 8
	};
	if (!g_state.ping_tgt_name || !g_state.rtt.data)
		error(1, errno, "fatal error");

	freeaddrinfo(tgtinfo);
	signal(SIGALRM, sigalrm_handler);
	signal(SIGINT, finish_ping);

	char ip_str_buf[3 * 4 + 4];
	inet_ntop(AF_INET, &g_state.ping_tgt_addr, ip_str_buf, sizeof(ip_str_buf));
	printf("PING %s (%s): %ld data bytes",
		g_state.ping_tgt_name, ip_str_buf, PACKET_LEN - sizeof(struct icmphdr));
	if (g_state.verbose)
		printf(", id 0x%04x = %d", g_state.pid, g_state.pid);
	putchar('\n');
	sigalrm_handler();
	// alarm(g_state.interval);

	receive_loop();
}

void	receive_loop()
{
	char				hostname[256];
	char				recv_buf[256];
	char				ip_str[INET_ADDRSTRLEN] = {0};
	struct sockaddr		recv_sockaddr = {};
	socklen_t			recv_socklen = sizeof(recv_sockaddr);

	while(true)
	{
		ssize_t bytes_recved = recvfrom(g_state.sockfd, recv_buf, sizeof(recv_buf), 0,
			&recv_sockaddr, &recv_socklen);
		if (bytes_recved < 0)
			error(3, errno, "recvfrom call failed");

		struct ip *ip = (struct ip*)recv_buf;
		if (ip->ip_p != IPPROTO_ICMP)
			return;
		// ip_hl: header length, number of 4-byte words in IP header.
		uint16_t ip_hdr_len = (ip->ip_hl * 4);
		struct icmp *icmp = (struct icmp*)(recv_buf + ip_hdr_len);

		if (!interesting_icmp(icmp->icmp_type))
			return;

		int gai_err;
		if ((gai_err = getnameinfo(&recv_sockaddr, recv_socklen, hostname, sizeof(hostname), NULL, 0, 0)) != EXIT_SUCCESS)
			error(3, 0, "getnameinfo() call failed: %s", gai_strerror(gai_err));

		printf("%zu bytes from %s: ", bytes_recved - ip_hdr_len, hostname);

		if (icmp->icmp_type == ICMP_ECHOREPLY)
		{
			if (icmp->icmp_id != (uint16_t)g_state.pid)
				return;

			struct timeval now = {}, delta = {};
			struct timeval *sent_time = (struct timeval*)icmp->icmp_data;
			gettimeofday(&now, NULL);
			timersub(&now, sent_time, &delta);
			float rtt_ms = ((float)delta.tv_sec * 1000.0f) + ((float)delta.tv_usec / 1000.0f);

			add_rtt_to_vector(&g_state.rtt, rtt_ms);

			g_state.received++;
			printf("icmp_seq=%d, ttl=%d, time=%.03f ms", icmp->icmp_seq, ip->ip_ttl, rtt_ms);
		}
		else
		{
			const char *msg = get_ICMP_msg_string(icmp->icmp_type, icmp->icmp_code);
			printf("%s", msg ? msg : "Unknown ICMP response");
		}
		printf("\n");
		if (g_state.verbose /*&& icmp->icmp_type != ICMP_ECHOREPLY*/)
			verbose_icmp_dump(icmp);
	}
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
		// receive_single(seq);
	}
	else if (g_state.num_to_send <= 0)
	{
		finish_ping();
	}
}

void	finish_ping()
{
	printf("--- %s ping statistics ---\n", g_state.ping_tgt_name);

	float packet_loss = (float)g_state.received / g_state.sent;
	packet_loss = 1.0f - (isnan(packet_loss) ? 0.0f : packet_loss);
	printf("%u packets transmitted, %u packets received, %.0f%% packet loss\n",
		g_state.sent, g_state.received, packet_loss * 100);

	if (g_state.received > 0)
	{
		float min_rtt = +INFINITY;
		float max_rtt = -INFINITY;
		float avg_rtt = 0.0f;
		for (size_t i = 0; i < g_state.rtt.size; ++i)
		{
			min_rtt = min_rtt > g_state.rtt.data[i] ? g_state.rtt.data[i] : min_rtt;
			max_rtt = max_rtt < g_state.rtt.data[i] ? g_state.rtt.data[i] : max_rtt;
			avg_rtt += g_state.rtt.data[i];
		}
		avg_rtt /= g_state.rtt.size;

		float squared_differences = 0.0f;
		for (size_t i = 0; i < g_state.rtt.size; ++i)
			squared_differences += powf(g_state.rtt.data[i] - avg_rtt, 2);
		float stddev = sqrtf(squared_differences / (g_state.rtt.size - 1));

		printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
			min_rtt, avg_rtt, max_rtt, stddev);
	}
	free(g_state.rtt.data);
	close(g_state.sockfd);
	exit(0);
}

void	verbose_icmp_dump(struct icmp *packet)
{
	// Check for all ICMP types that return original packet back into data segment
	if (!(packet->icmp_type == ICMP_DEST_UNREACH
		|| packet->icmp_type == ICMP_SOURCE_QUENCH
		|| packet->icmp_type == ICMP_REDIRECT
		|| packet->icmp_type == ICMP_TIME_EXCEEDED
		|| packet->icmp_type == ICMP_PARAMETERPROB))
	{
		return;
	}
	struct ip *orig_ip = (struct ip*)packet->icmp_data;
	uint ip_hdr_len = orig_ip->ip_hl * 4;

	/*
92 bytes from 192.168.190.72: Time to live exceeded
IP Hdr Dump:
 4500 0054 f3e7 4000 0101 1d43 c0a8 f32c 8efb 25ae
Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data
 4  5  00 0054 f3e7   2 0000  01  01 1d43 192.168.243.44  142.251.37.174
ICMP: type 8, code 0, size 64, id 0x7fec, seq 0x0000
	*/

	printf("IP Hdr Dump:\n ");
	for (uint i = 0; i < sizeof(struct iphdr); ++i)
		printf("%02x%s", *((unsigned char*)orig_ip + i), (i % 2 ? " " : ""));
	printf("\n");
	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
	printf (" %1x  %1x  %02x %04x %04x   %1x %04x  %02x  %02x %04x",
		orig_ip->ip_v,
		orig_ip->ip_hl,
		orig_ip->ip_tos,
		// ip_len byte order not consistent, guess order based on coherent size
		(orig_ip->ip_len > 0x2000) ? ntohs(orig_ip->ip_len) : orig_ip->ip_len,
		ntohs(orig_ip->ip_id),
		(ntohs(orig_ip->ip_off) & 0xe000) >> 13,
		ntohs(orig_ip->ip_off) & 0x1fff,
		orig_ip->ip_ttl,
		orig_ip->ip_p,
		ntohs(orig_ip->ip_sum)
	);
	printf (" %s ", inet_ntoa (*((struct in_addr *) &orig_ip->ip_src)));
	printf (" %s ", inet_ntoa (*((struct in_addr *) &orig_ip->ip_dst)));
	// Dump IP header options
	for (uint i = 0; i < ip_hdr_len - sizeof(struct iphdr); ++i)
		printf("%02x", *((char*)orig_ip + sizeof(struct iphdr) + i));
	printf("\n");

	struct icmp *orig_icmp = (struct icmp*)(packet->icmp_data + ip_hdr_len);
	printf("ICMP: type %u, code %u, size %d, id 0x%04x, seq 0x%04d",
		orig_icmp->icmp_type,
		orig_icmp->icmp_code,
		ntohs(orig_ip->ip_len) - ip_hdr_len,
		orig_icmp->icmp_id,
		orig_icmp->icmp_seq
	);
	printf("\n");
}
