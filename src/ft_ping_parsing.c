#include "ft_ping.h"

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include <error.h>
#include <getopt.h>

#define TTL_OPTION_FLAG	1

static const char help_str[] = "Usage: ping [OPTION...] HOST ...\n\
Send ICMP ECHO_REQUEST packets to network hosts.\n\
\n\
 Options valid for all request types:\n\
\n\
  -c, --count=NUMBER         stop after sending NUMBER packets\n\
  -i, --interval=NUMBER      wait NUMBER seconds between sending each packet\n\
  -n, --numeric              do not resolve host addresses\n\
      --ttl=N                specify N as time-to-live\n\
  -T, --tos=NUM              set type of service (TOS) to NUM\n\
  -v, --verbose              verbose output\n\
  -w, --timeout=N            stop after N seconds\n\
\n\
  -?, --help                 give this help list\n\
\n\
Report bugs to NOBODY I DON'T CARE.\
";

static int32_t parse_numerical_flag(char *arg, int32_t min, int32_t max)
{
	if (!arg)
		error(1, 0, "missing argument");
	char *endptr = NULL;
	long long res = strtoll(arg, &endptr, 10);
	if (*arg == '\0' || *endptr != '\0')
		error(1, 0, "invalid value (`%s' near `%s')", arg, endptr);
	else if (res < min)
		error(1, 0, "option value too small: %s", arg);
	else if (res > max)
		error(1, 0, "option value too big: %s", arg);
	return (int)res;
}

static struct option	long_options[] = {
	{.name = "count",		.has_arg = true,	.flag = NULL,	.val = 'c'},
	{.name = "interval",	.has_arg = true,	.flag = NULL,	.val = 'i'},
	{.name = "numeric",		.has_arg = false,	.flag = NULL,	.val = 'n'},
	{.name = "ttl",			.has_arg = true,	.flag = NULL,	.val = TTL_OPTION_FLAG},
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
		case TTL_OPTION_FLAG:	// TTL has no single char flag option
		{
			g_state.ttl = (uint8_t)parse_numerical_flag(optarg, 1, UINT8_MAX);
			break;
		}
		case 'c':
		{
			g_state.num_to_send = (sig_atomic_t)parse_numerical_flag(optarg, 1, SIG_ATOMIC_MAX);
			break;
		}
		case 'i':
		{
			g_state.interval = (uint32_t)parse_numerical_flag(optarg, 1, INT32_MAX);
			break;
		}
		case 'n':
		{
			g_state.numeric = true;
			break;
		}
		case 'T':
		{
			g_state.tos = (uint8_t)parse_numerical_flag(optarg, 0, UINT8_MAX);
			break;
		}
		case 'v':
			g_state.verbose = true;
			break;
		case 'w':
		{
			g_state.timeout = (int32_t)parse_numerical_flag(optarg, 1, INT32_MAX);
			break;
		}
		case '?':
		{
			switch (optopt)
			{
			case 0:	// optopt not set by --help
			case '?':
				puts(help_str);
				exit(0);
			default:
				puts("Try ping --help for more information");
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
