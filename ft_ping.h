#ifndef FT_PING
# define FT_PING
# define _GNU_SOURCE

# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <signal.h>
# include <stdbool.h>
# include <time.h>
# include <sys/time.h>

#define PACKET_LEN	(sizeof(struct icmphdr) + sizeof(struct timeval) + 40)
#define FTPING_ARRAY_SZ(a)	(sizeof(a) / sizeof(*a))

static inline bool	interesting_icmp(int type) {
	// TODO: Include more of these?
	return (type == ICMP_ECHOREPLY
		|| type == ICMP_DEST_UNREACH	// "Destination Host Unreachable"
		|| type == ICMP_TIME_EXCEEDED	// "Time to live exceeded"
	);
}

// What we need to remember about sent/received packets
struct packet_storage
{
	float	rtt;
	bool	received;	// Is used to detect duplicates
};

struct ft_ping_state
{
	// Volatile just in case signals fuck this up
	volatile sig_atomic_t	num_to_send;
	bool			verbose;
	uint32_t		ttl;
	unsigned int	interval;

	int				sockfd;
	struct sockaddr	sockaddr;

	pid_t			pid;
	char			*ping_tgt_name;
	struct in_addr	ping_tgt_addr;
	volatile uint	sent;
	unsigned int	received;

	struct Vector {	// Lightweight vector of each received packet's RTT
		float	*data;
		size_t	size;
		size_t	capacity;
	}	rtt;
};

extern struct ft_ping_state	g_state;

void		sigalrm_handler();
void		finish_ping();
void		receive_loop();
void		add_rtt_to_vector(struct Vector *vec, float rtt);
uint16_t	get_inet_checksum(void *addr, size_t count);
const char	*get_ICMP_msg_string(uint16_t icmp_type, uint16_t icmp_code);
void		verbose_icmp_dump(struct icmp *packet);

#endif
