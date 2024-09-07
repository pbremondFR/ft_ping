#include "ft_ping.h"

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include <error.h>
#include <getopt.h>

static const char help_str[] = R"(
Usage: ping [OPTION...] HOST ...
Send ICMP ECHO_REQUEST packets to network hosts.

 Options valid for all request types:

  -c, --count=NUMBER         stop after sending NUMBER packets
  -i, --interval=NUMBER      wait NUMBER seconds between sending each packet
  -n, --numeric              do not resolve host addresses
      --ttl=N                specify N as time-to-live
  -T, --tos=NUM              set type of service (TOS) to NUM
  -v, --verbose              verbose output
  -w, --timeout=N            stop after N seconds

  -?, --help                 give this help list

Report bugs to NOBODY I DON'T CARE.
)";

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

static struct option	long_options[] = {
	{.name = "count",		.has_arg = true,	.flag = NULL,	.val = 'c'},
	{.name = "interval",	.has_arg = true,	.flag = NULL,	.val = 'i'},
	{.name = "numeric",		.has_arg = false,	.flag = NULL,	.val = 'n'},
	{.name = "ttl",			.has_arg = true,	.flag = NULL,	.val = 1},
	{.name = "tos",			.has_arg = true,	.flag = NULL,	.val = 'T'},
	{.name = "verbose",		.has_arg = false,	.flag = NULL,	.val = 'v'},
	{.name = "timeout",		.has_arg = true,	.flag = NULL,	.val = 'w'},
	{.name = "help",		.has_arg = false,	.flag = NULL,	.val = '?'},
	{0, 0, 0, 0}	// null terminate LMAO
};

void	parse_options(int argc, char *const *argv)
{
	int	opt = 0;

	int	longopt_idx = 0;
	while ((opt = getopt_long(argc, argv, "c:i:nT:vw:", long_options, &longopt_idx)) != -1)
	{
		switch (opt)
		{
		case 1:	// TTL has no single char flag option
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
		case 'n':
		{
			g_state.numeric = true;
			break;
		}
		case 'T':
		{
			long tos = parse_numerical_flag(optarg);
			if (tos < 0 || tos > UINT8_MAX)
				error(1, 0, "invalid argument: '%ld': out of range: 0 <= value <= 255", tos);
			g_state.tos = tos;
			break;
		}
		case 'v':
			g_state.verbose = true;
			break;
		case '?':
		{
			switch (optopt)
			{
			case 0:	// optopt not set by --help
			case '?':
				puts(help_str);
				exit(0);
			default:
				puts("Try ping --help or ping --usage for more information");
				exit(64);
			}
		}
			exit(1);
			break;
		default:
			error(1, 0, "unknown option");
			break;
		}
	}

}
