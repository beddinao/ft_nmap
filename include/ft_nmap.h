#ifndef	FT_NMAP_H
#define	FT_NMAP_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <inttypes.h>
#include <time.h>
#include <sys/wait.h>
#include <pthread.h>

#ifndef	INTERFACE
# define	INTERFACE		"enp0s3"
#endif

#ifndef	SERVS_DATABASE
# define	SERVS_DATABASE	"database/services"
#endif

#ifndef	TCP_TIMEOUT
# define	TCP_TIMEOUT	1
#endif

#ifndef	ICMP_TIMEOUT
# define	ICMP_TIMEOUT	2
#endif

#define	PK_SIZE		2048
#define	MAX_PORTS		1024
#define	TCP_WIN_SIZE	65535
#define	AVA_SCANS		7
#define	PORT_STATES	10
#define	MAX_THREADS	255
#define	SRVS_MAX_LGH	20
#define	SRVSV_MAX_LGH	20
#define	MAX_PORT_SZ	15
#define	MIN_PORT_NUM	1
#define	MAX_PORT_NUM	65535
#define	MAX_TAR_LGH	255
#define	IFR_MAX_LGH	16
#define	ADDR_MAX_LGH	15

#define	NRMC		"\e[0m"
#define	WHTC		"\e[4;37m"

#ifndef	TERM_WIDTH
# define	TERM_WIDTH	111
#endif

#ifndef	DEBUG
# define	DEBUG		0
#endif

#ifndef	DEBUG_THREADS
# define	DEBUG_THREADS	0
#endif

#ifndef	true
# define	true		1
#endif

#ifndef	false
# define	false		0
#endif

typedef	int		bool;

typedef	enum	psatus {
	FAILURE,
	OPEN,
	CLOSED,
	FILTERED,
	OPEN_FILTERED,
	CLOSED_FILTERED,
	UNFILTERED,
	SUCCESS,
	NO_RESPONSE,
}	PStatus;

typedef	enum	tstatus {
	INIT,
	WAITING,
	RUNNING,
	FINISH,
}	TStatus;

typedef	enum	scansT {
	SYN,	// TCP 1-syn
	ACK,	// TCP 1-ack
	FIN,	// TCP 1-fin
	XMAS,	// TCP 1-urg, 1-fsh, 1-fin
	UDP,	// UDP
	CUST,	// --flags
	null,	// TCP 0-0
}	SType;

typedef	struct scan {
	struct	sockaddr_in	dst;
	struct	sockaddr_in	src;
	unsigned	int		port;
	SType			_scan_types[AVA_SCANS];
	PStatus			_scan_status[AVA_SCANS];
	unsigned	int		num_of_types;
	char			service[SRVS_MAX_LGH];
	char			service_version[SRVSV_MAX_LGH];
	PStatus			conclusion;
}	Scan;

typedef	struct	opts {
	bool		valid;
	bool		help;
	bool		verbose;
	char		target[MAX_TAR_LGH];
	int		min_port;
	int		max_port;
	int		total_ports;
	// scans
	bool		scans;
	int		num_of_scans;
	bool		SYN;
	bool		null;
	bool		FIN;
	bool		XMAS;
	bool		ACK;
	bool		UDP;
	bool		CUST;
	// flags
	bool		flags;
	bool		f_syn;
	bool		f_ack;
	bool		f_rst;
	bool		f_fin;
	bool		f_psh;
	bool		f_urg;
	// seq
	bool		seq;
	int		seq_num;
	// ack_seq
	bool		ack_seq;
	int		ack_seq_num;
	// threads
	bool		speedup;
	int		num_of_threads;
	//
	bool		interface;
	char		interface_name[IFR_MAX_LGH];
	//
	bool		source;
	char		source_addr[ADDR_MAX_LGH];
}	Options;

typedef	struct worker {
	unsigned	int	id;
	bool		alive;
	pthread_t		thread;
	pthread_mutex_t	mx;
	TStatus		t_status;
	Scan		*scan_start;
	Scan		*scan_end;
	Options		*input;
}	Worker;

typedef struct	pseudotcp {
	struct		in_addr	saddr;
	struct		in_addr	daddr;
	unsigned char		zero;
	unsigned char		protocol;
	unsigned short		length;
}	pseudohdr;

int	_icmp_check(struct sockaddr_in, struct addrinfo *, Options *);
PStatus	syn_scan(struct sockaddr_in, struct sockaddr_in, int, Options*);
PStatus	udp_scan(struct sockaddr_in, struct sockaddr_in, int, Options*);
PStatus	ack_scan(struct sockaddr_in, struct sockaddr_in, int, Options*);
PStatus	fin_null_xmas_scans(struct sockaddr_in, struct sockaddr_in, int, int, int, int, Options*);
PStatus	custom_scan(struct sockaddr_in, struct sockaddr_in, int, Options*);

void	print_results(Scan *, int, char *, clock_t);
void	print_help(bool);
int	print_scan_type(char *, SType, char *);
int	print_port_status(char *, PStatus, char *);
void	print_response_packets(struct tcphdr*, struct icmphdr*, int);
void      print_line(char, int, char *, char *, bool);

char		*itoa(char*, size_t, int, bool);
void		exit_call(char*, int);
unsigned short 	csum(unsigned short*, int);
char		*_interface_ip(char *, int);
struct addrinfo 	*getAddr(char *, char *, char **);
bool		look_up_service(int, bool, char **);
int		random_num();

void	parse_input(Options *, char **, int);

#endif
