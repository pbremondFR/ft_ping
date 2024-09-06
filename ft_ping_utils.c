#include "ft_ping.h"
#include <errno.h>
#include <stdlib.h>
#include <error.h>

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

// Hopefully everything that needs to be printed is in there.
const char	*get_ICMP_msg_string(uint16_t icmp_type, uint16_t icmp_code)
{
	typedef struct {
		uint16_t	code;
		const char	*str;
	} t_map;

	t_map	dest_unreach_strings[] = {
		{ICMP_HOST_UNREACH,		"Destination Host Unreachable"},
		{ICMP_PROT_UNREACH,		"Destination Protocol Unreachable"},
		{ICMP_PORT_UNREACH,		"Destination Port Unreachable"},
		{ICMP_FRAG_NEEDED,		"Fragmentation needed and DF set"},
		{ICMP_SR_FAILED,		"Source Route Failed"},
		{ICMP_NET_UNKNOWN,		"Network Unknown"},
		{ICMP_HOST_UNKNOWN,		"Host Unknown"},
		{ICMP_HOST_ISOLATED,	"Host Isolated"},
		{ICMP_NET_UNR_TOS,		"Destination Network Unreachable At This TOS"},
		{ICMP_HOST_UNR_TOS,		"Destination Host Unreachable At This TOS"},
		{ICMP_PKT_FILTERED,		"Packet Filtered"},
		{ICMP_PREC_VIOLATION,	"Precedence Violation"},
		{ICMP_PREC_CUTOFF,		"Precedence Cutoff"},
	};

	t_map	redirect_strings[] = {
		{ICMP_REDIR_NET,		"Redirect Network"},
		{ICMP_REDIR_HOST,		"Redirect Host"},
		{ICMP_REDIR_NETTOS,		"Redirect Type of Service and Network"},
		{ICMP_REDIR_HOSTTOS,	"Redirect Type of Service and Host"},
	};

	t_map	time_exceeded_strings[] = {
		{ICMP_EXC_TTL,		"Time to live exceeded"},
		{ICMP_EXC_FRAGTIME,	"Frag reassembly time exceeded"}
	};

	t_map	*icmp_msg = NULL;
	int		map_sz = 0;
	if (icmp_type == ICMP_DEST_UNREACH) {
		icmp_msg = dest_unreach_strings;
		map_sz = sizeof(dest_unreach_strings) / sizeof(t_map);
	} else if (icmp_type == ICMP_REDIRECT) {
		icmp_msg = redirect_strings;
		map_sz = sizeof(redirect_strings) / sizeof(t_map);
	} else if (icmp_type == ICMP_TIME_EXCEEDED) {
		icmp_msg = time_exceeded_strings;
		map_sz = sizeof(time_exceeded_strings) / sizeof(t_map);
	}
	for (; icmp_msg && icmp_msg < icmp_msg + map_sz; ++icmp_msg)
		if (icmp_msg->code == icmp_code)
			break;
	return icmp_msg ? icmp_msg->str : NULL;
}

void	add_rtt_to_vector(struct Vector *vec, float rtt)
{
	if (vec->size == vec->capacity)
	{
		vec->data = reallocarray(vec->data, vec->capacity * 2, sizeof(vec->data[0]));
		if (!vec->data)
		{
			vec->data = reallocarray(vec->data, ++vec->capacity, sizeof(vec->data[0]));
			if (!vec->data)
				error(1, errno, "failed to store RTT");
		}
		else
			vec->capacity *= 2;
	}
	vec->data[vec->size++] = rtt;
	return;
}
