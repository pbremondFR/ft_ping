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
		uint16_t	type;
		uint16_t	code;
	}	type_code_pair;

	const uint16_t icmp_code_wildcard = UINT16_MAX;

	static const struct {type_code_pair key; const char* value;}	strings[] = {
		/* Destination Unreachable (code 3) */
		{{ICMP_DEST_UNREACH, ICMP_HOST_UNREACH},	"Destination Host Unreachable"},
		{{ICMP_DEST_UNREACH, ICMP_PROT_UNREACH},	"Destination Protocol Unreachable"},
		{{ICMP_DEST_UNREACH, ICMP_PORT_UNREACH},	"Destination Port Unreachable"},
		{{ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED},		"Fragmentation needed and DF set"},
		{{ICMP_DEST_UNREACH, ICMP_SR_FAILED},		"Source Route Failed"},
		{{ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN},		"Network Unknown"},
		{{ICMP_DEST_UNREACH, ICMP_HOST_UNKNOWN},	"Host Unknown"},
		{{ICMP_DEST_UNREACH, ICMP_HOST_ISOLATED},	"Host Isolated"},
		{{ICMP_DEST_UNREACH, ICMP_NET_UNR_TOS},		"Destination Network Unreachable At This TOS"},
		{{ICMP_DEST_UNREACH, ICMP_HOST_UNR_TOS},	"Destination Host Unreachable At This TOS"},
		{{ICMP_DEST_UNREACH, ICMP_PKT_FILTERED},	"Packet Filtered"},
		{{ICMP_DEST_UNREACH, ICMP_PREC_VIOLATION},	"Precedence Violation"},
		{{ICMP_DEST_UNREACH, ICMP_PREC_CUTOFF},		"Precedence Cutoff"},
		/* Source Quench (code 4): DEPRECATED */
		{{ICMP_SOURCE_QUENCH, icmp_code_wildcard},	"Source Quench"},
		/* Redirect (change route) (code 5) */
		{{ICMP_REDIRECT, ICMP_REDIR_NET},		"Redirect Network"},
		{{ICMP_REDIRECT, ICMP_REDIR_HOST},		"Redirect Host"},
		{{ICMP_REDIRECT, ICMP_REDIR_NETTOS},	"Redirect Type of Service and Network"},
		{{ICMP_REDIRECT, ICMP_REDIR_HOSTTOS},	"Redirect Type of Service and Host"},
		/* Time Exceeded (code 11) */
		{{ICMP_TIME_EXCEEDED, ICMP_EXC_TTL},		"Time to live exceeded"},
		{{ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME},	"Frag reassembly time exceeded"},
		/* Parameter Problem (code 12) */
		{{ICMP_PARAMETERPROB, icmp_code_wildcard},	"Parameter Problem"},
		/* Timestamp Request/Reply (codes 13/14) */
		{{ICMP_TIMESTAMP,		icmp_code_wildcard},	"Timestamp Request"},
		{{ICMP_TIMESTAMPREPLY,	icmp_code_wildcard},	"Timestamp Reply"},
		/* Information Request/Reply (codes 15/16): DEPRECATED */
		{{ICMP_INFO_REQUEST,	icmp_code_wildcard},	"Information Request"},
		{{ICMP_INFO_REPLY,		icmp_code_wildcard},	"Information Reply"},
		/* Address Mask Request/Reply (codes 17/18): DEPRECATED */
		{{ICMP_ADDRESS,			icmp_code_wildcard},	"Address Mask Request"},
		{{ICMP_ADDRESSREPLY,	icmp_code_wildcard},	"Address Mask Reply"},
	};

	type_code_pair to_find = {icmp_type, icmp_code};
	const char *msg = NULL;
	for (size_t i = 0; i < FTPING_ARRAY_SZ(strings); ++i)
	{
		if (to_find.type == strings[i].key.type
			&& (to_find.code == strings[i].key.code || strings[i].key.code == icmp_code_wildcard))
		{
			msg = strings[i].value;
			break;
		}
	}
	return msg;
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
