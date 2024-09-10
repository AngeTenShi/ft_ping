#include "ft_ping.h"

void print_usage(void)
{
	printf("Usage: ft_ping [-h] [-c count] [-s packetsize] [--ttl ttl] [-v] [-w timeout] [-n] hostname\n");
	printf("Options:\n");
	printf("  -h\t\t\t\tPrint help and exit\n");
	printf("  -c count\t\t\tStop after sending count ECHO_REQUEST packets\n");
	printf("  -s packetsize\t\t\tSpecify the number of data bytes to be sent\n");
	printf("  --ttl ttl\t\t\tSet the IP Time to Live\n");
	printf("  -v\t\t\t\tVerbose output\n");
	printf("  -w timeout\t\t\tTime to wait for a response, in seconds\n");
	printf("  -n\t\t\t\tPrint only IP addresses\n");
}

void parse_args(int ac, char **av, t_options *options)
{
	int i = 0;
	while (i < ac)
	{
		if (av[i][0] == '-')
		{
			if (av[i][1] == 'h')
			{
				print_usage();
				free(options);
				exit(0);
			}
			else if (av[i][1] == 'c')
			{
				if (i + 2 >= ac)
				{
					printf("ping: usage error: Destination address required\n");
					free(options);
					exit(1);
				}
				options->nb_packets = atoi(av[i + 1]);
				if (options->nb_packets < 1 || options->nb_packets > 9223372036854775807)
				{
					char *error = malloc(100);
					if (av[i + 1][0] != '0' && options->nb_packets == 0)
						sprintf(error, "invalid argument: '%s'", av[i + 1]);
					else
						sprintf(error, "invalid argument: '%s': out of range: 1 <= value <= 9223372036854775807", av[i + 1]);
					print_error(error);
					free(options);
					free(error);
					exit(1);
				}
				i++;
			}
			else if (av[i][1] == 's')
			{
				if (i + 2 >= ac)
				{
					printf("ping: usage error: Destination address required\n");
					free(options);
					exit(1);
				}
				options->packet_size = atoi(av[i + 1]);
				if (options->packet_size < 0 || options->packet_size > 2147483647)
				{
					char *error = malloc(100);
					if (av[i + 1][0] != '0' && options->packet_size == 0)
						sprintf(error, "invalid argument: '%s'", av[i + 1]);
					else
						sprintf(error, "invalid argument: '%s': out of range: 0 <= value <= 65507", av[i + 1]);
					print_error(error);
					free(options);
					free(error);
					exit(1);
				}
				i++;
			}
			else if (av[i][1] == '-')
			{
				if (strncmp(av[i], "--ttl", 5) == 0 && strlen(av[i]) == 5)
				{
					if (i + 2 >= ac)
					{
						printf("ping: usage error: Destination address required\n");
						free(options);
						exit(1);
					}
					options->ttl = atoi(av[i + 1]);
					if (options->ttl < 0 || options->ttl > 255)
					{
						char *error = malloc(100);
						if (av[i + 1][0] != '0' && options->ttl == 0)
							sprintf(error, "invalid argument: '%s'", av[i + 1]);
						else
							sprintf(error, "invalid argument: '%s': out of range: 0 <= value <= 255", av[i + 1]);
						print_error(error);
						free(options);
						free(error);
						exit(1);
					}
					i++;
				}
			}
			else if (av[i][1] == 'v')
				options->verbose = 1;
			else if (av[i][1] == 'w')
			{
				if (i + 2 >= ac)
				{
					printf("ping: usage error: Destination address required\n");
					free(options);
					exit(1);
				}
				options->timeout_ping = atoi(av[i + 1]);
				if (options->timeout_ping < 0 || options->timeout_ping > 2147483647)
				{
					char *error = malloc(100);
					if (av[i + 1][0] != '0' && options->timeout_ping == 0)
						sprintf(error, "invalid argument: '%s'", av[i + 1]);
					else
						sprintf(error, "invalid argument: '%s': out of range: 0 <= value <= 2147483647", av[i + 1]);
					print_error(error);
					free(options);
					free(error);
					exit(1);
				}
			}
			else if (av[i][1] == 'n')
				options->print_only_ip = 1;
			else
			{
				print_usage();
				free(options);
				exit(1);
			}
		}
		i++;
	}
}

t_options *init_options()
{
	t_options *options;

	options = malloc(sizeof(t_options));
	options->nb_packets = -1;
	options->packet_size = 56; // 64 with ICMP header
	options->ttl = 63;
	options->verbose = 0;
	options->timeout_ping = 0;
	options->print_only_ip = 0;
	return (options);
}

void print_error(char *msg)
{
	printf("ping: %s\n", msg);
	exit(1);
}

double sqrt(double x)
{
	double z = 1;
	for (int i = 0; i < 10; i++)
		z -= (z * z - x) / (2 * z);
	return z;
}
