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
	packet = (char *)malloc(packet_size + sizeof(struct icmphdr));
	icmp = (struct icmphdr *)packet;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = sequence_number;
	icmp->un.echo.id = getpid();
	memset(packet + sizeof(struct icmphdr), 1, packet_size);
	icmp->checksum = checksum((unsigned short *)packet, packet_size + sizeof(struct icmphdr));
	return (packet);
}

void calculate_metrics(struct timespec time_start, double *sum_rtt_squared, double *avg_rtt, double *max_rtt, double *min_rtt, long double *rtt_msec)
{
	struct timespec time_end;
	clock_gettime(CLOCK_MONOTONIC, &time_end);
	double time_diff = (double)(time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
	*rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + (time_diff);
	*sum_rtt_squared += *rtt_msec * *rtt_msec;
	if (*rtt_msec > *max_rtt)
		*max_rtt = *rtt_msec;
	if (*rtt_msec < *min_rtt || *min_rtt == 0)
		*min_rtt = *rtt_msec;
	*avg_rtt += *rtt_msec;
}

void print_dump_packet(char *recv_packet, char *packet)
{
	// Cast the packet to an IP header structure
	const struct iphdr *ip = (struct iphdr *)recv_packet;
	// Calculate the header length in bytes
	size_t hlen = ip->ihl << 2;
	// Pointer to the start of the IP payload
	const uint8_t *cp = (uint8_t *)ip + hlen;

	// Print the IP header in hexadecimal format
	printf("IP Hdr Dump:\n");
	for (int i = 0; i < 10; i++)
		printf(" %04x", ((uint16_t *)ip)[i]);
	printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");

	// Print the IP header fields in a human-readable format
	printf(" %1x  %1x  %02x", ip->version, ip->ihl, ip->tos);
	printf(" %04x %04x", (ip->tot_len > 0x2000) ? ntohs(ip->tot_len) : ip->tot_len, ntohs(ip->id));
	printf("   %1x %04x", (ntohs(ip->frag_off) & 0xe000) >> 13, ntohs(ip->frag_off) & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ntohs(ip->check));
	printf(" %s ", inet_ntoa(*((struct in_addr *)&ip->saddr)));
	printf(" %s ", inet_ntoa(*((struct in_addr *)&ip->daddr)));

	// Print the remaining header bytes in hexadecimal format
	while (hlen-- > sizeof(struct iphdr))
		printf("%02x", *cp++);
	printf("\n");

	// ICMP INFOS
	printf("ICMP : ");
	struct icmphdr *icmp = (struct icmphdr *)(packet);
	printf("type %d, code %d, size %d, id 0x%x, seq 0x%04x\n", icmp->type, icmp->code, ntohs(ip->tot_len) - (ip->ihl << 2) - 20 - 8, icmp->un.echo.id, icmp->un.echo.sequence);

	printf("\n");
}

void ft_ping(int socket_fd, struct sockaddr_in *ping_addr, char *dest_addr, t_options *opts)
{
	int ttl;
	long double msg_count = 0;
	int msg_received_count = 0;
	struct sockaddr_in r_addr;
	char *packet;
	struct timeval tv_out;
	struct timespec time_start, g_start, g_end;
	double min_rtt = 0;
	double max_rtt = 0;
	double avg_rtt = 0;
	double sum_rtt_squared = 0;
	tv_out.tv_sec = 1;
	tv_out.tv_usec = 0;
	ttl = opts->ttl;
	int sent = 0;
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
	char *dest_ip = dns_lookup(dest_addr, ping_addr);
	if (dest_ip == NULL)
	{
		print_error("unknown host");
		return ;
	}
	int addr_len = sizeof(r_addr);
	printf("PING %s (%s): %d data bytes", dest_addr, dest_ip, opts->packet_size);
	if (opts->verbose)
		printf(", id 0x%x = %d\n", getpid(), getpid());
	else
		printf("\n");
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
		packet = create_packet(msg_count - 1, opts->packet_size);
		clock_gettime(CLOCK_MONOTONIC, &time_start);
		if (sendto(socket_fd, packet, opts->packet_size + sizeof(struct icmphdr), 0, (struct sockaddr *)ping_addr, sizeof(*ping_addr)) <= 0)
			sent = 0;

		fd_set read_fds;
		struct timeval timeout;
		FD_ZERO(&read_fds);
		FD_SET(socket_fd, &read_fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		int select_result = select(socket_fd + 1, &read_fds, NULL, NULL, &timeout);
		if (select_result > 0 && FD_ISSET(socket_fd, &read_fds))
		{
			char *recv_packet = (char *)malloc(0x10000);
			size_t bytes_received = recvfrom(socket_fd, recv_packet, 0x10000, 0, (struct sockaddr *)&r_addr, (socklen_t *)&addr_len);
			if (bytes_received > 0)
			{
				struct iphdr *ip = (struct iphdr *)recv_packet;
				struct icmphdr *icmp = (struct icmphdr *)(recv_packet + (ip->ihl << 2));
				ttl = ip->ttl;
				int size = ntohs(ip->tot_len) - (ip->ihl << 2);
				if (!do_ping || (opts->nb_packets == msg_received_count && opts->nb_packets != -1))
				{
					if (packet)
						free(packet);
					if (recv_packet)
						free(recv_packet);
					break;
				}
				if (sent)
				{
					struct icmphdr *icmp_from = (struct icmphdr *)(packet);
					int packet_from_id = icmp_from->un.echo.id;
					char *recv_ip = dns_lookup(inet_ntoa(r_addr.sin_addr), &r_addr);
					if (recv_ip == NULL)
						recv_ip = inet_ntoa(r_addr.sin_addr);
					char *recv_hostname = reverse_dns_lookup(recv_ip);
					if (recv_hostname == NULL)
						recv_hostname = recv_ip;
					long double rtt_msec = 0;
					calculate_metrics(time_start, &sum_rtt_squared, &avg_rtt, &max_rtt, &min_rtt, &rtt_msec);
					if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == packet_from_id)
					{
						if (opts->print_only_ip == 0)
							printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3Lf ms\n",  size, recv_hostname, recv_ip, (int)(msg_count - 1), ttl, rtt_msec);
						else
							printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3Lf ms\n", size, recv_ip, (int)(msg_count - 1), ttl, rtt_msec);
						msg_received_count++;
					}
					else if (icmp->type == ICMP_DEST_UNREACH)
					{
						if (opts->print_only_ip == 0)
							printf("%d bytes from %s (%s): Destination Host Unreachable\n", size, recv_hostname, recv_ip);
						else
							printf("%d bytes from %s: Destination Host Unreachable\n", size, recv_ip);
						if (opts->verbose)
							print_dump_packet(recv_packet, packet);
					}
					else if (icmp->type == ICMP_TIME_EXCEEDED)
					{
						if (opts->print_only_ip == 0)
							printf("%d bytes from %s (%s): Time to live exceeded\n", size, recv_hostname, recv_ip);
						else
							printf("%d bytes from %s: Time to live exceeded\n", size, recv_ip);
					}
					else if (icmp->type == NR_ICMP_UNREACH)
					{
						if (opts->print_only_ip == 0)
							printf("%d bytes from %s (%s): Network Unreachable\n", size, recv_hostname, recv_ip);
						else
							printf("%d bytes from %s: Network Unreachable\n", size, recv_ip);
					}
					else
					{
						if (icmp->un.echo.id != icmp_from->un.echo.id || icmp->un.echo.sequence != icmp_from->un.echo.sequence)
						{
							free(packet);
							free(recv_packet);
							msg_count--;
							continue;
						}
					}
					if (recv_ip)
						free(recv_ip);
					if (recv_hostname != recv_ip)
						free(recv_hostname);
				}
				usleep(1000000);
			}
			free(recv_packet);
		}
		else if (select_result == 0)
		{
			if (!do_ping)
			{
				if (packet)
					free(packet);
				break;
			}
		}
		free(packet);
		packet = NULL;
	}
	free(dest_ip);
	clock_gettime(CLOCK_MONOTONIC, &g_end);
	double time_taken = (double)(g_end.tv_nsec - g_start.tv_nsec) / 1000000.0;
	long double total_msec = (g_end.tv_sec - g_start.tv_sec) * 1000.0 + (time_taken);
	printf("\n--- %s ping statistics ---\n", dest_addr);
	printf("%d packets transmitted, %d received, %d%% packet loss, time %d ms\n", (int)msg_count, msg_received_count, (int)(((msg_count - msg_received_count) / msg_count) * 100.0), (int)total_msec);
	if (msg_received_count > 0)
	{
		avg_rtt /= msg_count;
		double mdev = sqrt((sum_rtt_squared / msg_received_count) - (avg_rtt * avg_rtt)); // sqrt of variance
		printf("rtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", min_rtt, avg_rtt, max_rtt, mdev);
	}
}

int main(int ac, char **av)
{
	t_options *options;
	char *dest_addr;
	struct sockaddr_in addr_con;
	int socket_fd;
	if (ac < 2)
	{
		print_error("usage error: Destination address required");
		return (1);
	}
	options = init_options();
	parse_args(ac, av, options);
	dest_addr = av[ac - 1];
	socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (socket_fd < 0)
	{
		print_error("Lack of privileges must run as root");
		free(options);
		return (1);
	}
	signal(SIGINT, interrupt_handler);
	ft_ping(socket_fd, &addr_con, dest_addr, options);
	free(options);
	close(socket_fd);
	return (0);
}
