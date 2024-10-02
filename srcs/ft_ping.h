#ifndef FT_PING_H
# define FT_PING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <time.h>
typedef struct options
{
	long double nb_packets; // -c
	int packet_size; // -s
	int ttl; // --ttl
	int verbose; // -v
	int timeout_ping_dead; // -w
	int print_only_ip; // -n
} t_options;

typedef struct packet
{
	struct icmphdr hdr;
	char *msg;
} t_packet;

void print_usage(void);
void parse_args(int ac, char **av, t_options *options);
t_options *init_options();
void print_error(char *error);
double sqrt(double x);
int	is_ipv4(char *ip);
void parse_fdqn(char **dest_addr);

#endif
