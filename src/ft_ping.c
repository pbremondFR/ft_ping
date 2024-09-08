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
	.numeric = false,
	.ttl = 112,
	.tos = 0,
	.interval = 1,
	.timeout = -1,

	.sockfd = 0,
	.sockaddr = {},

	.pid = 0,
	.ping_tgt_name = NULL,
	.ping_tgt_addr = {},
	.sent = 0,
	.received = 0,
	.started_at = {},
	.packets = {
		.data = NULL,
		.capacity = 0,
	},
};

int	main(int argc, char *const *argv)
{
	parse_options(argc, argv);

	if (optind == argc)
		error(1, 0, "missing host operand");

	struct addrinfo hints = {};
	struct addrinfo *tgtinfo;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW; // XXX: 0 of SOCK_RAW?
	hints.ai_protocol = 0;
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

	int gai_error = getaddrinfo(argv[optind], NULL, &hints, &tgtinfo);
	if (gai_error != 0)
		error(1, 0, "unknown host: %s", gai_strerror(gai_error));

	struct sockaddr_in *ipv4 = (struct sockaddr_in*)tgtinfo->ai_addr;

	g_state.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (g_state.sockfd == -1)
		error(1, errno, "failed to create socket");
	if (setsockopt(g_state.sockfd, SOL_IP, IP_TTL, &g_state.ttl, sizeof(g_state.ttl)) != 0)
		error(1, errno, "setsockopt IP_TTL");
	if (setsockopt(g_state.sockfd, SOL_IP, IP_TOS, &g_state.tos, sizeof(g_state.tos)) != 0)
		error(1, errno, "setsockopt IP_TOS");

	g_state.pid = getpid();
	g_state.sockaddr = *(struct sockaddr*)ipv4;
	g_state.ping_tgt_addr = ipv4->sin_addr;
	g_state.ping_tgt_name = argv[optind];
	g_state.packets = (struct PacketStorageVector){
		.data = calloc(16, sizeof(struct packet_storage)),
		.capacity = 16,
	};
	if (!g_state.ping_tgt_name || !g_state.packets.data)
		error(1, errno, "fatal error");

	freeaddrinfo(tgtinfo);
	signal(SIGALRM, sigalrm_handler);
	signal(SIGINT, finish_ping);

	char ip_str_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &g_state.ping_tgt_addr, ip_str_buf, sizeof(ip_str_buf));
	printf("PING %s (%s): %ld data bytes",
		g_state.ping_tgt_name, ip_str_buf, PACKET_LEN - sizeof(struct icmphdr));
	if (g_state.verbose)
		printf(", id 0x%04x = %d", g_state.pid, g_state.pid);
	printf("\n");
	gettimeofday(&g_state.started_at, NULL);
	sigalrm_handler();

	receive_loop();
}

void	receive_loop()
{
	char				hostname[256] = {};
	char				recv_buf[256] = {};
	struct sockaddr		recv_sockaddr = {};
	socklen_t			recv_socklen = sizeof(recv_sockaddr);

	while(true)
	{
		ssize_t bytes_recved = recvfrom(g_state.sockfd, recv_buf, sizeof(recv_buf), 0,
			&recv_sockaddr, &recv_socklen);
		if (bytes_recved < 0)
			error(1, errno, "recvfrom failed");

		struct ip *ip = (struct ip*)recv_buf;
		if (ip->ip_p != IPPROTO_ICMP)
			return;
		// ip_hl: header length, number of 4-byte words in IP header.
		uint16_t ip_hdr_len = (ip->ip_hl * 4);
		struct icmp *icmp = (struct icmp*)(recv_buf + ip_hdr_len);

		int gai_flags = g_state.numeric ? NI_NUMERICHOST : 0;
		int gai_err = getnameinfo(&recv_sockaddr, recv_socklen, hostname, sizeof(hostname), NULL, 0, gai_flags);
		if (gai_err != 0)
			error(1, 0, "getnameinfo failed: %s", gai_strerror(gai_err));

		// Packet too short to contain ICMP header
		if (bytes_recved - ip_hdr_len < (ssize_t)sizeof(struct icmphdr))
		{
			fprintf(stderr, "packet too short (%ld bytes) from %s\n", bytes_recved - ip_hdr_len, hostname);
			continue;
		}

		// If ICMP Data segment is too short, checksum will not match so that also checks it
		uint16_t cksum = icmp->icmp_cksum;
		icmp->icmp_cksum = 0;
		if (cksum != get_inet_checksum(icmp, bytes_recved - ip_hdr_len))
			fprintf(stderr, "checksum mismatch from %s\n", hostname);
		icmp->icmp_cksum = cksum;	// Restore it just in case we use it later for some reason

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
			printf("icmp_seq=%d, ttl=%d, time=%.03f ms", icmp->icmp_seq, ip->ip_ttl, rtt_ms);

			if (add_packet_to_vector(rtt_ms, icmp->icmp_seq) == true)
				printf(" (DUP!)");
			g_state.received++;
		}
		else
		{
			const char *msg = get_ICMP_msg_string(icmp->icmp_type, icmp->icmp_code);
			printf("%s", msg ? msg : "Unknown ICMP response");
		}
		printf("\n");
		if (g_state.verbose && icmp->icmp_type != ICMP_ECHOREPLY)
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
		// Finish ping after N seconds if enabled
		if (g_state.timeout != -1)
		{
			struct timeval now, elapsed;
			gettimeofday(&now, NULL);
			timersub(&now, &g_state.started_at, &elapsed);
			if (elapsed.tv_sec >= g_state.timeout)
				finish_ping();
		}
		uint16_t seq = g_state.sent++;
		send_ping(seq);
		alarm(g_state.interval);
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

	// Calculations are not really efficient if many packets are dropped but that's not important
	if (g_state.received > 0)
	{
		float min_rtt = +INFINITY;
		float max_rtt = -INFINITY;
		float avg_rtt = 0.0f;
		uint16_t num_packets = 0;
		for (size_t i = 0; i < g_state.packets.capacity; ++i)
		{
			struct packet_storage *p = &g_state.packets.data[i];
			if (!p->received)	// Skip over unreceived packets, if any.
				continue;
			++num_packets;
			min_rtt = min_rtt > p->rtt ? p->rtt : min_rtt;
			max_rtt = max_rtt < p->rtt ? p->rtt : max_rtt;
			avg_rtt += p->rtt;
		}
		avg_rtt /= num_packets;

		float squared_differences = 0.0f;
		for (size_t i = 0; i < g_state.packets.capacity; ++i)
		{
			if (!g_state.packets.data[i].received)	// Skip over unreceived packets, if any.
				continue;
			squared_differences += powf(g_state.packets.data[i].rtt - avg_rtt, 2);
		}
		float stddev = sqrtf(squared_differences / (num_packets - 1));

		printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
			min_rtt, avg_rtt, max_rtt, stddev);
	}
	free(g_state.packets.data);
	close(g_state.sockfd);
	exit(0);
}

void	verbose_icmp_dump(struct icmp *recved_packet)
{
	// Check for all ICMP types that return original packet back into data segment
	if (!(recved_packet->icmp_type == ICMP_DEST_UNREACH
		|| recved_packet->icmp_type == ICMP_SOURCE_QUENCH
		|| recved_packet->icmp_type == ICMP_REDIRECT
		|| recved_packet->icmp_type == ICMP_TIME_EXCEEDED
		|| recved_packet->icmp_type == ICMP_PARAMETERPROB))
	{
		return;
	}
	struct ip *orig_ip = (struct ip*)recved_packet->icmp_data;
	uint ip_hdr_len = orig_ip->ip_hl * 4;

	printf("IP Hdr Dump:\n ");
	for (uint i = 0; i < sizeof(struct iphdr); ++i)
		printf("%02x%s", *((u_char*)orig_ip + i), (i % 2 ? " " : ""));
	printf("\n");
	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
	printf (" %1x  %1x  %02x %04x %04x   %1x %04x  %02x  %02x %04x",
		orig_ip->ip_v,
		orig_ip->ip_hl,		// Version + IHL == 8 bits, no byte order swap
		orig_ip->ip_tos,	// TOS is 8 bits, no byte order swap
		ntohs(orig_ip->ip_len),
		ntohs(orig_ip->ip_id),
		// Flags are the 3 most signficant bits of 'IP offset' field
		(ntohs(orig_ip->ip_off) & ~IP_OFFMASK) >> 13,
		ntohs(orig_ip->ip_off) & IP_OFFMASK,
		orig_ip->ip_ttl,	// 8 bits, no byte order swap
		orig_ip->ip_p,		// 8 bits, no byte order swap
		ntohs(orig_ip->ip_sum)
	);

	char	src_ip_str[INET_ADDRSTRLEN] = {0};
	char	dst_ip_str[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &orig_ip->ip_src, src_ip_str, sizeof(src_ip_str));
	inet_ntop(AF_INET, &orig_ip->ip_dst, dst_ip_str, sizeof(dst_ip_str));
	printf(" %s  %s ", src_ip_str, dst_ip_str);

	// Dump IP header options
	for (uint i = 0; i < ip_hdr_len - sizeof(struct iphdr); ++i)
		printf("%02x", *((char*)orig_ip + sizeof(struct iphdr) + i));
	printf("\n");

	struct icmp *orig_icmp = (struct icmp*)(recved_packet->icmp_data + ip_hdr_len);
	printf("ICMP: type %u, code %u, size %d, id 0x%04x, seq 0x%04d",
		orig_icmp->icmp_type,
		orig_icmp->icmp_code,
		// Only convert IP byte order, ICMP is a copy of our own sent packet.
		ntohs(orig_ip->ip_len) - ip_hdr_len,
		orig_icmp->icmp_id,
		orig_icmp->icmp_seq
	);
	printf("\n");
}
