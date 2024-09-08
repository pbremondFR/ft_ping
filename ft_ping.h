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

// What we need to remember about sent/received packets
struct packet_storage
{
	float	rtt;
	bool	received;	// Is used to detect duplicates
};

// Lightweight Vector storing data about RTT and duplicated packets
// Store each packet's RTT at the index of its ICMP sequence, and set
// 'received' to true. If it's already true, then you have a duplicate packet.
struct PacketStorageVector
{
	struct packet_storage	*data;
	size_t	capacity;
};

struct ft_ping_state
{
	// Volatile just in case signals fuck this up
	volatile sig_atomic_t	num_to_send;
	bool			verbose;
	bool			numeric;	// TODO: Don't resolve host address?
	uint32_t		ttl;
	uint32_t		tos;
	unsigned int	interval;
	int				timeout;

	int				sockfd;
	struct sockaddr	sockaddr;

	pid_t			pid;
	char			*ping_tgt_name;
	struct in_addr	ping_tgt_addr;
	volatile uint	sent;
	unsigned int	received;

	struct PacketStorageVector	packets;
};

extern struct ft_ping_state	g_state;

void		parse_options(int argc, char *const *argv);
void		sigalrm_handler();
void		finish_ping();
void		receive_loop();
bool		add_packet_to_vector(float rtt, uint16_t icmp_sequence);
uint16_t	get_inet_checksum(void *addr, size_t count);
const char	*get_ICMP_msg_string(uint16_t icmp_type, uint16_t icmp_code);
void		verbose_icmp_dump(struct icmp *packet);

#endif
