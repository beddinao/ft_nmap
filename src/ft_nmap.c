#include "ft_nmap.h"

int	send_packet(int protocol, struct sockaddr_in daddr, struct sockaddr_in saddr, int dport, int seq, int ack_seq,
	int syn, int ack, int rst, int fin, int psh, int urg, bool verbose) {

	char		packet[PK_SIZE];
	char		se_packet[PK_SIZE];
	int		sock;
	struct	tcphdr	*tcp_hdr;
	struct	udphdr	*udp_hdr;
	struct	iphdr	*ip_hdr;
	pseudohdr		*pseudo;
	int		trsphdr_size = protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr);
	int		iphdr_size = sizeof(struct iphdr);
	int		pseudo_size = sizeof(pseudohdr);
	socklen_t		addr_size = sizeof(struct sockaddr_in);
	int		_ip_tos = IPTOS_LOWDELAY, _incd_ip_hdrs = 1;

	memset(packet, 0, PK_SIZE);
	memset(se_packet, 0, PK_SIZE);
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)	return -1;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, &_ip_tos, sizeof(_ip_tos)) < 0
		|| setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &_incd_ip_hdrs, sizeof(_incd_ip_hdrs)) < 0) {
		close(sock);
		return -1;
	}

	if (verbose && protocol == IPPROTO_TCP)
		printf("-> TCP [%i] syn: %i | ack: %i | rst: %i | fin: %i | psh: %i | urg: %i | seq: %i | ack_seq: %i | window: %i\n",
			dport, syn, ack, rst, fin, psh, urg, seq, ack_seq, TCP_WIN_SIZE);
	else if (verbose && protocol == IPPROTO_UDP) printf("-> UDP [%i]\n", dport);

	ip_hdr = (struct iphdr*)packet;
	tcp_hdr = (struct tcphdr*)(packet + iphdr_size);
	udp_hdr = (struct udphdr*)(packet + iphdr_size);
	pseudo = (pseudohdr*)se_packet;

	pseudo->saddr = saddr.sin_addr;
	pseudo->daddr = daddr.sin_addr;
	pseudo->protocol = protocol;
	pseudo->length = htons(trsphdr_size);

	ip_hdr->version = 4;
	ip_hdr->id = htons(random_num());
	ip_hdr->protocol = protocol;
	ip_hdr->saddr = saddr.sin_addr.s_addr;
	ip_hdr->daddr = daddr.sin_addr.s_addr;
	ip_hdr->ihl = iphdr_size / 4;
	ip_hdr->ttl = IPDEFTTL;
	ip_hdr->tot_len = htons(iphdr_size + trsphdr_size);

	if (protocol == IPPROTO_TCP) {
		tcp_hdr->source = htons(random_num());
		tcp_hdr->dest = htons(dport);
		tcp_hdr->seq = htonl(seq);
		tcp_hdr->ack_seq = htonl(ack_seq);
		tcp_hdr->syn = syn;
		tcp_hdr->ack = ack;
		tcp_hdr->rst = rst;
		tcp_hdr->fin = fin;
		tcp_hdr->psh = psh;
		tcp_hdr->urg = urg;
		tcp_hdr->window = htons(TCP_WIN_SIZE);
		tcp_hdr->doff = trsphdr_size / 4;
	}
	else if (protocol == IPPROTO_UDP) {
		udp_hdr->source = htons(random_num());
		udp_hdr->dest = htons(dport);
		udp_hdr->len = htons(trsphdr_size);
	}

	memcpy(se_packet + sizeof(pseudohdr), packet + iphdr_size, trsphdr_size);

	if (protocol == IPPROTO_TCP)
		tcp_hdr->check = csum((unsigned short*)se_packet, (sizeof(pseudohdr) + trsphdr_size) /2);
	else if (protocol == IPPROTO_UDP)
		udp_hdr->check = csum((unsigned short*)se_packet, (sizeof(pseudohdr) + trsphdr_size) /2);

	ip_hdr->check = csum((unsigned short*)packet, iphdr_size/2);

	if (sendto(sock, packet, iphdr_size + trsphdr_size, 0, (struct sockaddr*)&daddr, addr_size) < 0) {
		close(sock);
		return -1;
	}
	close(sock);
	return	0;
}

int	recv_x_packet(struct tcphdr *res_tcp_hdr, struct udphdr *res_udp_hdr, struct icmphdr *res_icmp_hdr,
		struct sockaddr_in *from, struct sockaddr_in daddr, int dport, int timeout) {
	char		packet[PK_SIZE];
	int		sock;
	struct	iphdr	ip_hdr;
	int		tcphdr_size = sizeof(struct tcphdr);
	int		iphdr_size = sizeof(struct iphdr);
	int		udphdr_size = sizeof(struct udphdr);
	int		ethhdr_size = sizeof(struct ethhdr);
	socklen_t		addr_size = sizeof(struct sockaddr_in);

	if ((sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) return -1;
	for (time_t init_time = time(NULL);(time(NULL) - init_time) < (float)timeout;) {
		memset(packet, 0, sizeof(packet));
		if (recvfrom(sock, packet, PK_SIZE, 0, (struct sockaddr*)from, &addr_size) < 0) {
			close(sock);
			return	-1;
		}
		memset(&ip_hdr, 0, iphdr_size);
		memcpy(&ip_hdr, packet + ethhdr_size, iphdr_size);
		if (ip_hdr.saddr == daddr.sin_addr.s_addr) {
			if (res_tcp_hdr && ip_hdr.protocol == IPPROTO_TCP) {
				struct	tcphdr	tcp_hdr;
				memset(&tcp_hdr, 0, tcphdr_size);
				memcpy(&tcp_hdr, packet + ethhdr_size + iphdr_size, tcphdr_size);
				if (ntohs(tcp_hdr.source) == dport) {
					memcpy(res_tcp_hdr, &tcp_hdr, tcphdr_size);
					close(sock);
					return	1;
				}
			}
			else if (res_udp_hdr && ip_hdr.protocol == IPPROTO_UDP) {
				struct	udphdr	udp_hdr;
				memset(&udp_hdr, 0, udphdr_size);
				memcpy(&udp_hdr, packet + ethhdr_size + iphdr_size, udphdr_size);
				if (ntohs(udp_hdr.source) == dport) {
					memcpy(res_udp_hdr, &udp_hdr, udphdr_size);
					close(sock);
					return	2;
				}
			}
			else if (res_icmp_hdr && ip_hdr.protocol == IPPROTO_ICMP) {
				memcpy(res_icmp_hdr, packet + ethhdr_size + iphdr_size, sizeof(struct icmphdr));
				close(sock);
				return	3;
			}
		}
	}
	close(sock);
	return	0;
}

int	_icmp_check(struct sockaddr_in src, struct addrinfo *dest, Options *input) {
	char		packet[PK_SIZE];
	struct		icmphdr	in_icmphdr;
	socklen_t		a_si = sizeof(struct addrinfo);
	size_t		icmphdr_size = sizeof(struct icmphdr);
	int		sock, inc_ip_hdrs = 0, _i;
	struct	timeval	tv;
	fd_set		r_set;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock < 0)	return -1;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &inc_ip_hdrs, sizeof(inc_ip_hdrs)) < 0) {
		close(sock);
		return -1;
	}

	memset(packet, 0, sizeof(packet));
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = ICMP_TIMEOUT;

	struct	icmphdr *icmp_hdr = (struct icmphdr*)packet;
	icmp_hdr->type = ICMP_ECHO;
	icmp_hdr->un.echo.id = random_num();
	icmp_hdr->un.echo.sequence = 65;
	icmp_hdr->checksum = csum((unsigned short *)packet, icmphdr_size/2);

	_i = sendto(sock, packet, icmphdr_size, 0, dest->ai_addr, a_si);
	if (_i < 0) {
		close(sock);
		return -1;
	}

	printf("icmp_echo request sent..\n");

	FD_ZERO(&r_set);
	FD_SET(sock, &r_set);
	_i = select(sock + 1, &r_set, NULL, NULL, &tv);
	if (_i <= 0) {
		close(sock);
		return _i < 0 ? -1 : 0;
	}
	
	memset(packet, 0, sizeof(packet));
	_i = recvfrom(sock, packet, PK_SIZE, 0, dest->ai_addr, &a_si);
	if (_i < 0) {
		close(sock);
		return -1;
	}

	close(sock);

	memset(&in_icmphdr, 0, icmphdr_size);
	memcpy(&in_icmphdr, packet + sizeof(struct iphdr), icmphdr_size);

	printf("%s echo.id=%i, icmp_seq=%i\n",
		(in_icmphdr.type == ICMP_ECHOREPLY) ? "icmp_echoreply": "icmp_reply",
		in_icmphdr.un.echo.id, in_icmphdr.un.echo.sequence);

	if (in_icmphdr.type == ICMP_ECHOREPLY)
		return	1;
	return	0;
}

// ( syn, ack, rst, fin, psh, urg )

PStatus	syn_scan(struct sockaddr_in src, struct sockaddr_in dst, int port, Options *input) {
	struct	tcphdr		tcp_hdr;
	struct	icmphdr		icmp_hdr;
	struct	udphdr		udp_hdr;
	struct	sockaddr_in	source;
	PStatus			pS = CLOSED_FILTERED;
	pid_t			pid;
	int			_res = 0;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&udp_hdr, 0, sizeof(udp_hdr));
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	memset(&source, 0, sizeof(source));

	pid = fork();
	if (!pid) {
		send_packet(IPPROTO_TCP, dst, src, port, input->seq_num, input->ack_seq_num, 1, 0, 0, 0, 0, 0, input->verbose);
		exit(0);
	}
	else if (pid < 0)	return FAILURE;
	_res = recv_x_packet(&tcp_hdr, NULL, &icmp_hdr, &source, dst, port, ICMP_TIMEOUT);
	waitpid(pid, NULL, 0);

	if (_res < 0) 	return FAILURE;
	else if (!_res
	|| (_res == 3 && icmp_hdr.type == ICMP_DEST_UNREACH
		&& (icmp_hdr.code == ICMP_NET_UNREACH
		|| icmp_hdr.code == ICMP_HOST_UNREACH
		|| icmp_hdr.code == ICMP_PROT_UNREACH
		|| icmp_hdr.code == ICMP_PORT_UNREACH
		|| icmp_hdr.code == ICMP_NET_ANO
		|| icmp_hdr.code == ICMP_HOST_ANO
		|| icmp_hdr.code == ICMP_PKT_FILTERED)))	pS = FILTERED;
	else if (tcp_hdr.rst)		pS = CLOSED;
	else if ((tcp_hdr.syn && tcp_hdr.ack)
	|| tcp_hdr.syn /*split handshake*/)	pS = OPEN;

	if (input->verbose) print_response_packets(_res == 1 ? &tcp_hdr : NULL, _res == 3 ? &icmp_hdr : NULL, port);
	return	pS;
}

PStatus	ack_scan(struct sockaddr_in src, struct sockaddr_in dst, int port, Options *input) {
	struct	tcphdr	tcp_hdr;
	struct	icmphdr	icmp_hdr;
	struct	sockaddr_in	source;
	PStatus			pS = CLOSED_FILTERED;
	pid_t			pid;
	int			_res = 0;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	memset(&source, 0, sizeof(source));

	pid = fork();
	if (!pid) {
		send_packet(IPPROTO_TCP, dst, src, port, input->seq_num, input->ack_seq_num, 0, 1, 0, 0, 0, 0, input->verbose);
		exit(0);
	}
	else if (pid < 0)	return FAILURE;
	_res = recv_x_packet(&tcp_hdr, NULL, &icmp_hdr, &source, dst, port, ICMP_TIMEOUT);
	waitpid(pid, NULL, 0);

	if (_res < 0)	return FAILURE;
	if (tcp_hdr.rst)		pS = UNFILTERED;
	else if (!_res
	|| (_res == 3 && icmp_hdr.type == 3
		&& (icmp_hdr.code == 0
		 || icmp_hdr.code == 1
		 || icmp_hdr.code == 2
		 || icmp_hdr.code == 3
		 || icmp_hdr.code == 9
		 || icmp_hdr.code == 10
		 || icmp_hdr.code == 13)))	pS = FILTERED;

	if (input->verbose) print_response_packets(_res == 1 ? &tcp_hdr : NULL, _res == 3 ? &icmp_hdr : NULL, port);
	return	pS;
}

PStatus	custom_scan(struct sockaddr_in src, struct sockaddr_in dst, int port, Options *input) {
	struct	tcphdr	tcp_hdr;
	struct	icmphdr	icmp_hdr;
	struct	sockaddr_in	source;
	PStatus		pS = SUCCESS;
	pid_t		pid;
	int		_res = 0;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	memset(&source, 0, sizeof(source));

	pid = fork();
	if (!pid) {
		send_packet(IPPROTO_TCP, dst, src, port, input->seq_num, input->ack_seq_num,
			input->f_syn, input->f_ack, input->f_rst, input->f_fin, input->f_psh, input->f_urg, input->verbose);
		exit(0);
	}
	else if (pid < 0)	return FAILURE;
	_res = recv_x_packet(&tcp_hdr, NULL, &icmp_hdr, &source, dst, port, ICMP_TIMEOUT);
	waitpid(pid, NULL, 0);

	if (_res < 0)	return FAILURE;
	else if (!_res)	pS = NO_RESPONSE;

	print_response_packets(_res == 1 ? &tcp_hdr: NULL, _res == 3 ? &icmp_hdr:NULL, port);
	return	pS;
}

PStatus	fin_null_xmas_scans(struct sockaddr_in src, struct sockaddr_in dst, int port, int fin, int psh, int urg, Options *input) {
	struct	tcphdr		tcp_hdr;
	struct	icmphdr		icmp_hdr;
	struct	sockaddr_in	source;
	PStatus			pS = CLOSED_FILTERED;
	pid_t			pid;
	int			_res = 0;

	memset(&tcp_hdr, 0, sizeof(tcp_hdr));
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	memset(&source, 0, sizeof(source));

	pid = fork();
	if (!pid) {
		send_packet(IPPROTO_TCP, dst, src, port, input->seq_num, input->ack_seq_num, 0, 0, 0, fin, psh, urg, input->verbose);
		exit(0);
	}
	else if (pid < 0) return FAILURE;
	_res = recv_x_packet(&tcp_hdr, NULL, &icmp_hdr, &source, dst, port, TCP_TIMEOUT);
	waitpid(pid, NULL, 0);

	if (_res < 0)	return FAILURE;
	if (_res == 3 && icmp_hdr.type == 3
		&& (icmp_hdr.code == 0
		|| icmp_hdr.code == 1
		|| icmp_hdr.code == 2
		|| icmp_hdr.code == 3
		|| icmp_hdr.code == 9
		|| icmp_hdr.code == 10
		|| icmp_hdr.code == 13))	pS = FILTERED;
	else if (!_res) 			pS = OPEN_FILTERED;
	else if (tcp_hdr.rst)		pS = CLOSED;

	if (input->verbose) print_response_packets(_res == 1 ? &tcp_hdr : NULL, _res == 3 ? &icmp_hdr : NULL, port);
	return	pS;
}

PStatus	udp_scan(struct sockaddr_in src, struct sockaddr_in dst, int port, Options *input) {
	int			_res = 0;
	struct	icmphdr		icmp_hdr;
	struct	udphdr		udp_hdr;
	struct	sockaddr_in	source;
	pid_t			pid;
	PStatus			pS = CLOSED_FILTERED;

	memset(&udp_hdr, 0, sizeof(udp_hdr));
	memset(&icmp_hdr, 0, sizeof(icmp_hdr));
	memset(&source, 0, sizeof(source));

	pid = fork();
	if (!pid) {
		send_packet(IPPROTO_UDP, dst, src, port, 0, 0, 0, 0, 0, 0, 0, 0, input->verbose);
		exit(0);
	}
	else if (pid < 0) return FAILURE;
	_res = recv_x_packet(NULL, &udp_hdr, &icmp_hdr, &source, dst, port, ICMP_TIMEOUT);
	waitpid(pid, NULL, 0);

	if (_res < 0) return FAILURE;
	if (!_res)				pS = OPEN_FILTERED;
	else if (icmp_hdr.type == ICMP_DEST_UNREACH
		&& icmp_hdr.code == ICMP_PORT_UNREACH)	pS = CLOSED;
	else if (_res == 2)			pS = OPEN;
	else if (icmp_hdr.type == ICMP_DEST_UNREACH
		&& (icmp_hdr.code == 0
		|| icmp_hdr.code == 1
		|| icmp_hdr.code == 2
		|| icmp_hdr.code == 9
		|| icmp_hdr.code == 10
		|| icmp_hdr.code == 13))	pS = FILTERED;

	if (input->verbose) print_response_packets(NULL, _res == 3 ? &icmp_hdr : NULL, port);
	return	pS;
}


