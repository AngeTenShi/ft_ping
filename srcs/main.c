#include "ft_ping.h"

int do_ping = 1;

unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;
	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return (result);
}

void interrupt_handler(int sig)
{
	(void)sig;
	do_ping = 0;
}

char *reverse_dns_lookup(char *ip)
{
	struct sockaddr_in temp_addr;
	socklen_t len;
	char buf[NI_MAXHOST], *ret_buf;
	temp_addr.sin_family = AF_INET;
	temp_addr.sin_addr.s_addr = inet_addr(ip);
	len = sizeof(struct sockaddr_in);
	if (getnameinfo((struct sockaddr *)&temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD))
		return (NULL);
	ret_buf = (char *)malloc((strlen(buf) + 1) * sizeof(char));
	strcpy(ret_buf, buf);
	return (ret_buf);
}

char *dns_lookup(char *addr, struct sockaddr_in *addr_con)
{
	// get the ip address of the host from the hostname with getaddrinfo
	struct addrinfo hints = {0}, *res = NULL;
	int ret = 0;
	char ip[INET_ADDRSTRLEN];
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(addr, NULL, &hints, &res);
	if (ret != 0)
		return (NULL);
	char *ret_buf = NULL;
	struct addrinfo *p = res;
	struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
	void *address = &(ipv4->sin_addr);
	inet_ntop(p->ai_family, address, ip, sizeof(ip));
	ret_buf = (char *)malloc((strlen(ip) + 1) * sizeof(char));
	strcpy(ret_buf, ip);
	memcpy(addr_con, ipv4, sizeof(struct sockaddr_in));
	freeaddrinfo(res);
	return (ret_buf);
}

char *create_packet(int sequence_number, int packet_size)
{
	char *packet;
	struct icmphdr *icmp;
	packet = (char *)malloc(packet_size);
	icmp = (struct icmphdr *)packet;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = sequence_number;
	icmp->un.echo.id = getpid();
	memset(packet + sizeof(struct icmphdr), 0, packet_size - sizeof(struct icmphdr));
	icmp->checksum = checksum((unsigned short *)packet, packet_size);
	return packet;
}

void ft_ping(int socket_fd, struct sockaddr_in *ping_addr, char *orig_host, char *dest_host, char *dest_ip, t_options *opts)
{
	int ttl;
	long double msg_count = 0;
	int addr_len, msg_received_count = 0;
	struct sockaddr_in r_addr;
	char *packet;
	struct timeval tv_out;
	struct timespec time_start, time_end, g_start, g_end;
	double min_rtt = 0;
	double max_rtt = 0;
	double avg_rtt = 0;
	double sum_rtt_squared = 0;
	tv_out.tv_sec = 1;
	tv_out.tv_usec = 0;
	ttl = opts->ttl;
	int sent;
	if (setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
	{
		print_error("Setting socket options to TTL failed");
		return;
	}
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out)) != 0)
	{
		print_error("Setting socket options to timeout failed");
		return;
	}
	addr_len = sizeof(r_addr);
	if (opts->verbose)
	{
		printf("ping : sock4.fd= %d (socktype : SOCK_RAW), hints.ai_family: AF_INET (not UNSPEC because only IPV4)\n\n", socket_fd);
		printf("ai->ai_family: AF_INET, ai->ai_canonname: '%s'\n", orig_host);
	}
	printf("PING %s (%s) %d(%d) bytes of data.\n", orig_host, dest_ip, opts->packet_size, opts->packet_size + 8 + 20); // 8 bytes ICMP header and 20 bytes IP header
	if (opts->timeout_ping_dead != 0)
	{
		alarm(opts->timeout_ping_dead);
		signal(SIGALRM, interrupt_handler);
	}
	clock_gettime(CLOCK_MONOTONIC, &g_start);
	while ((do_ping && opts->nb_packets == -1) || (do_ping && (msg_count < opts->nb_packets)))
	{
		sent = 1;
		msg_count++;
		packet = create_packet(msg_count, opts->packet_size);
		struct icmphdr *icmp = (struct icmphdr *)packet;
		int packet_id = icmp->un.echo.id;
		clock_gettime(CLOCK_MONOTONIC, &time_start);
		if (sendto(socket_fd, packet, opts->packet_size, 0, (struct sockaddr *)ping_addr, sizeof(*ping_addr)) <= 0)
			sent = 0;
		if (recvfrom(socket_fd, packet, opts->packet_size, 0, (struct sockaddr *)&r_addr, (socklen_t *)&addr_len) <= 0)
		{
			if (!do_ping)
				break;
		}
		else
		{
			clock_gettime(CLOCK_MONOTONIC, &time_end);
			double time_diff = (double)(time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
			long double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + (time_diff);
			sum_rtt_squared += rtt_msec * rtt_msec;
			if (rtt_msec > max_rtt)
				max_rtt = rtt_msec;
			if (rtt_msec < min_rtt || min_rtt == 0)
				min_rtt = rtt_msec;
			avg_rtt += rtt_msec;
			if (!do_ping || (opts->nb_packets == msg_received_count && opts->nb_packets != -1))
				break;
			if (sent)
			{
				if (opts->print_only_ip == 0)
				{
					if (opts->verbose)
						printf("%d bytes from %s (%s): icmp_seq=%d ident=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_host, dest_ip, (int)msg_count, packet_id, ttl, rtt_msec);
					else
						printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_host, dest_ip, (int)msg_count, ttl, rtt_msec);
				}
				else
				{
					if (opts->verbose)
						printf("%d bytes from %s: icmp_seq=%d ident=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_ip, (int)msg_count, packet_id, ttl, rtt_msec);
					else
						printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_ip, (int)msg_count, ttl, rtt_msec);
				}
			}
			msg_received_count++;
			usleep(1000000);
		}
		free(packet);
	}
	clock_gettime(CLOCK_MONOTONIC, &g_end);
	double time_taken = (double)(g_end.tv_nsec - g_start.tv_nsec) / 1000000.0;
	long double total_msec = (g_end.tv_sec - g_start.tv_sec) * 1000.0 + (time_taken);
	printf("\n--- %s ping statistics ---\n", orig_host);
	printf("%d packets transmitted, %d received, %d%% packet loss, time %d ms\n", (int)msg_count, msg_received_count, (int)(((msg_count - msg_received_count) / msg_count) * 100.0), (int)total_msec);
	if (msg_received_count > 0)
	{
		avg_rtt /= msg_count;
		double mdev = sqrt((sum_rtt_squared / msg_received_count) - (avg_rtt * avg_rtt)); // sqrt of variance
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min_rtt, avg_rtt, max_rtt, mdev);
	}
}

int main(int ac, char **av)
{
	t_options *options;
	char *dest_addr;
	struct sockaddr_in addr_con;
	char *ip_addr = NULL;
	char *hostname;
	char *orig_host;
	int socket_fd;
	if (ac < 2)
	{
		print_error("usage error: Destination address required");
		return (1);
	}
	options = init_options();
	parse_args(ac, av, options);
	dest_addr = av[ac - 1];
	parse_fdqn(&dest_addr); // remove http:// or https:// or www. from the address
	orig_host = dest_addr;
	ip_addr = dns_lookup(dest_addr, &addr_con);
	if (ip_addr == NULL)
	{
		char *error = malloc(100 + strlen(dest_addr));
		sprintf(error, "%s: Name or service not known", dest_addr);
		print_error(error);
		free(error);
		free(options);
		return (1);
	}
	hostname = reverse_dns_lookup(ip_addr);
	if (hostname == NULL)
	{
		if (strncmp(ip_addr, dest_addr, strlen(dest_addr)) == 0)
			hostname = ip_addr;
		else
			hostname = dest_addr;
	}
	if (getuid() != 0)
	{
		print_error("You must be root to use ping");
		free(options);
		free(hostname);
		free(ip_addr);
		return (1);
	}
	socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	signal(SIGINT, interrupt_handler);
	ft_ping(socket_fd, &addr_con, orig_host, hostname, ip_addr, options);
	free(options);
	close(socket_fd);
	free(hostname);
	free(ip_addr);
	return (0);
}
