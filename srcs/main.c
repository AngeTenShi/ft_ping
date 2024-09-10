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

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) {
    struct hostent *host_entity;
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));

    if ((host_entity = gethostbyname(addr_host)) == NULL) {
        return (NULL);
    }
    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr)); // Convert IP into string
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons(0);
    (*addr_con).sin_addr.s_addr = *(long *)host_entity->h_addr; // Copy IP address from DNS to addr_con

    return ip;
}

char *create_packet(int sequence_number, int packet_size)
{
	char *packet;
	struct icmp *icmp;
	packet = (char *)malloc(packet_size);
	icmp = (struct icmp *)packet;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = sequence_number;
	icmp->icmp_id = getpid();
	memset(icmp->icmp_data, 0, packet_size);
	icmp->icmp_cksum = checksum((unsigned short *)packet, packet_size);
	return (packet);
}

void ft_ping(int socket_fd, struct sockaddr_in *ping_addr, char *dest_host, char *dest_ip, t_options *opts)
{
	int ttl;
	int msg_count = 0;
	int addr_len, msg_received_count = 0;
	struct sockaddr_in r_addr;
	char *packet;
	struct timeval tv_out;
	struct timespec time_start, time_end, g_start, g_end;
	double min_rtt = 0;
	double max_rtt = 0;
	double avg_rtt = 0;
	tv_out.tv_sec = opts->timeout_ping;
	tv_out.tv_usec = 0;
	ttl = opts->ttl;
	int sent;
	if (setsockopt(socket_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
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
	printf("PING %s (%s) %d(%d) bytes of data.\n", dest_host, dest_ip, opts->packet_size, opts->packet_size + 8 + 20);
	clock_gettime(CLOCK_MONOTONIC, &g_start);
	while (do_ping)
	{
		sent = 1;
		msg_count++;
		packet = create_packet(msg_count, opts->packet_size);
		clock_gettime(CLOCK_MONOTONIC, &time_start);
		if (sendto(socket_fd, packet, opts->packet_size, 0, (struct sockaddr *)ping_addr, sizeof(*ping_addr)) <= 0)
			sent = 0;
		if (recvfrom(socket_fd, packet, opts->packet_size, 0, (struct sockaddr *)&r_addr, (socklen_t *)&addr_len) <= 0 && msg_count > 1)
			printf("Packet receive failed\n");
		else
		{
			clock_gettime(CLOCK_MONOTONIC, &time_end);
			double time_diff = (double)(time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
			long double rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + (time_diff);
			if (rtt_msec > max_rtt)
				max_rtt = rtt_msec;
			if (rtt_msec < min_rtt || min_rtt == 0)
				min_rtt = rtt_msec;
			avg_rtt += rtt_msec;
			if (!do_ping)
				break;
			if (sent)
			{
				if (opts->print_only_ip == 0)
					printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_host, dest_ip, msg_count, ttl, rtt_msec);
				else
					printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1Lf ms\n", opts->packet_size + 8, dest_ip, msg_count, ttl, rtt_msec);
			}
			msg_received_count++;
		}
		free(packet);
		usleep(1000000); // to avoid flooding the network
	}
	clock_gettime(CLOCK_MONOTONIC, &g_end);
	double time_taken = (double)(g_end.tv_nsec - g_start.tv_nsec) / 1000000.0;
	long double total_msec = (g_end.tv_sec - g_start.tv_sec) * 1000.0 + (time_taken);
	printf("\n--- %s ping statistics ---\n", dest_host);
	printf("%d packets transmitted, %d received, %d%% packet loss, time %d ms\n", msg_count, msg_received_count, (int)(((msg_count - msg_received_count) / msg_count) * 100.0), (int)total_msec);
	if (msg_received_count > 0)
	{
		avg_rtt /= msg_received_count;
		double mdev = sqrt(pow(avg_rtt - min_rtt, 2) + pow(avg_rtt - max_rtt, 2)); // TODO check if this is correct
		printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min_rtt, avg_rtt, max_rtt, mdev);
	}
}

int main(int ac, char **av)
{
	t_options *options;
	char *dest_addr;
	struct sockaddr_in addr_con;
	char *ip_addr;
	char *hostname;
	int socket_fd;
	if (ac < 2)
	{
		print_error("usage error: Destination address required");
		return (1);
	}
	options = init_options();
	parse_args(ac, av, options);
	dest_addr = av[ac - 1];
	ip_addr = dns_lookup(dest_addr, &addr_con);
	if (ip_addr == NULL)
	{
		print_error("usage error: Destination address required");
		free(options);
		return (1);
	}
	hostname = reverse_dns_lookup(ip_addr);
	if (hostname == NULL)
		hostname = ip_addr;
	socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	signal(SIGINT, interrupt_handler);
	ft_ping(socket_fd, &addr_con, hostname, ip_addr, options);
	free(ip_addr);
	free(options);
	return (0);
}
