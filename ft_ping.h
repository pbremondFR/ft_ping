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
};

extern struct ft_ping_state	g_state;

void	sigalrm_handler();
void	finish_ping();
void	receive_loop();

#endif
