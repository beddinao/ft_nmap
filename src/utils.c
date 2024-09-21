#include "ft_nmap.h"

char      *itoa(char *s, size_t s_s, int n, bool t) {
	int       si = 0, sn = n;
	while (sn) { sn /= 10; si++; }
	if (t) si++;
	if (si > s_s) si = s_s;
	s[si--] = '\0';
	if (!n) s[si] = '0';
	else while (n && si) {
		s[si--] = (n % 10) + 48;
		n /= 10;
	}
	if (t) s[si] = '\t';
}

void	exit_call(char *msg, int status) {
	if (status < 0)	printf("%s\n", msg);
	else		perror(msg);
	status = abs(status);
	if (status)
		exit(status);
}

unsigned	short csum(unsigned short *buf, int nwords) {
	unsigned	long sum = 0;
	for (; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return	(unsigned short)(~sum);
}

char	*_interface_ip(char *ifr, int ip_protocol) {
	struct	ifreq	ifr_ip;
	int	sock;

	memset(&ifr_ip, 0, sizeof(ifr_ip));
	if ((sock = socket(AF_INET, SOCK_RAW, ip_protocol)) < 0) exit_call("socket() failure", 1);
	strncpy(ifr_ip.ifr_name, ifr, strlen(ifr));
	if(ioctl(sock, SIOCGIFADDR, &ifr_ip) != 0) exit_call("ioctl() failure", 1);
	close(sock);

	return inet_ntoa(((struct sockaddr_in*)&ifr_ip.ifr_addr)->sin_addr);
}

struct	addrinfo *getAddr(char *host, char *port, char **dest_ip) {
	struct	addrinfo	hints;
	struct	addrinfo	*res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_PASSIVE;
	int _i = getaddrinfo(host, port, &hints, &res);
	if (_i != 0 || !res) return	NULL;
	if (dest_ip)	*dest_ip = inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr);
	return	res;
}

bool	look_up_service(int p, bool is_udp, char **output) {
	char	*line = NULL, *sub_, *o;
	char	_port[MAX_PORT_SZ];
	int	read, found = false;
	size_t	len = 0, l;
	FILE	*f;

	memset(*output, 0, sizeof(*output));
	f = fopen(SERVS_DATABASE, "r");
	if (!f)  found = false;
	else {
		memset(_port, 0, sizeof(_port));
		itoa(_port, sizeof(_port), p, true);
		o = strcat(_port, is_udp ? "/udp" : "/tcp");
		while ((read = getline(&line, &len, f)) != -1) {
			if ((sub_ = strstr(line, o)) != NULL) {
				l = sub_ - line;
				if (l > 19) l = 19;
				memcpy(*output, line, l);
				found = true;
			}
		}
		free(line);
		fclose(f);
	}
	return found;
}

int	random_num() {
	return	random() % (MAX_PORT_NUM - 1024) + 1024;
}
