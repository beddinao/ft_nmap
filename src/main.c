#include "ft_nmap.h"

void	*_scan_routine(void *arg) {
	bool		is_udp = false;
	Worker		*self_data = (Worker*)arg;
	Scan		*scan_data = self_data->scan_start;
	Options		*scan_input = self_data->input;
	int		cons[PORT_STATES] = {0}, conclusion;
	char		*p;

	for (int cur_type = 0; cur_type < scan_data->num_of_types; cur_type++) {
		switch (scan_data->_scan_types[cur_type]) {
			case SYN: scan_data->_scan_status[cur_type] = syn_scan(scan_data->src, scan_data->dst, scan_data->port, scan_input); break;
			case ACK: scan_data->_scan_status[cur_type] = ack_scan(scan_data->src, scan_data->dst, scan_data->port, scan_input); break;
			case UDP: is_udp = (scan_data->_scan_status[cur_type] = udp_scan(scan_data->src, scan_data->dst, scan_data->port, scan_input)) == OPEN; break;
			case FIN: scan_data->_scan_status[cur_type] = fin_null_xmas_scans(scan_data->src, scan_data->dst, scan_data->port, 1, 0, 0, scan_input); break;
			case null: scan_data->_scan_status[cur_type] = fin_null_xmas_scans(scan_data->src, scan_data->dst, scan_data->port, 0, 0, 0, scan_input); break;
			case XMAS: scan_data->_scan_status[cur_type] = fin_null_xmas_scans(scan_data->src, scan_data->dst, scan_data->port, 1, 1, 1, scan_input); break;
			case CUST: scan_data->_scan_status[cur_type] = custom_scan(scan_data->src, scan_data->dst, scan_data->port, scan_input); break;
		}
		cons[ scan_data->_scan_status[cur_type] ] += 1;
	}

	conclusion = cons[0];

	for (int cur_state = 0; cur_state < PORT_STATES; cur_state++)
		if (cons[cur_state] > conclusion) {
			conclusion = cons[cur_state];
			scan_data->conclusion = cur_state;
			if (cur_state == OPEN)	break;
		}

	p = scan_data->service;
	if (!look_up_service(scan_data->port, is_udp, &p)) 
		memcpy(p, "unknown", 7);

	pthread_mutex_lock(&self_data->mx);
	self_data->t_status = FINISH;
	pthread_mutex_unlock(&self_data->mx);
}

bool	prepare_configuration(Options *input, SType *scan_types, struct addrinfo *dest, struct sockaddr_in src) {
	FILE	*f;
	int	is_host_up;

	printf("Configurations:\n");
	printf("Target Ip-Address: %s\n", inet_ntoa(((struct sockaddr_in*)dest->ai_addr)->sin_addr));
	printf("Source Ip-Address: %s\n", inet_ntoa(src.sin_addr));

	if (!input->source_ip) {
		printf("Using Interface: %s\n", input->interface_name);
		print_line('.', TERM_WIDTH / 5, NULL, NULL, true);
		is_host_up = _icmp_check(src, dest, input);
		printf("Host State: %s\n", is_host_up > 0 ? "Up" : !is_host_up ? "Down" : "Check Fail");
		if (is_host_up <= 0)
			return	false;
	}

	if (input->source_port)
		printf("Source port: %i\n", input->source_port_num);

	print_line('.', TERM_WIDTH / 5, NULL, NULL, true);
	printf("No of Ports to scan: %i\n", input->total_ports);
	printf("No of threads: %i\n", input->num_of_threads);
	f = fopen(SERVS_DATABASE, "r");
	printf("Using known services database: %s\n", f ? SERVS_DATABASE : "non-present");
	fclose(f);
	
	if (input->flags)
		printf("Tcp Flags header: {syn: %i, ack: %i, rst: %i, fin: %i, psh: %i, urg: %i}\n",
			input->f_syn, input->f_ack, input->f_rst, input->f_fin, input->f_psh, input->f_urg);
	
	printf("Scans to be performed: ");
	for (int cur_type = 0; cur_type < input->num_of_scans; cur_type++) {
		if (input->SYN && !(input->SYN = 0)) scan_types[cur_type] = SYN;
		else if (input->ACK && !(input->ACK = 0)) scan_types[cur_type] = ACK;
		else if (input->null && !(input->null = 0)) scan_types[cur_type] = null;
		else if (input->XMAS && !(input->XMAS = 0)) scan_types[cur_type] = XMAS;
		else if (input->UDP && !(input->UDP = 0)) scan_types[cur_type] = UDP;
		else if (input->FIN && !(input->FIN = 0)) scan_types[cur_type] = FIN;
		else if (input->CUST && !(input->CUST = 0)) scan_types[cur_type] = CUST;
		print_scan_type(NULL, scan_types[cur_type], " ");
	}
	printf("\n");

	printf("Scanning...\n");
	return	true;
}

int	main(int c, char **v) {

	if (c < 2) {
		print_help(false);
		return 1;
	}

	Options		input;
	memset(&input, 0, sizeof(input));

	parse_input(&input, v, c);

	if (input.help) {
		print_help(true);
		return 0;
	}

	if (!input.valid) {
		write(2, "\nsee --help for usage instructions\n", 35);
		return 1;
	}

	struct	addrinfo		*dest;
	struct	sockaddr_in	dst;
	struct	sockaddr_in	src;

	if (!(dest = getAddr(input.target, NULL, NULL)))
		exit_call("can\'t resolve address / getaddrinfo() failure", -1);

	memset(&dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));
	dst.sin_family = AF_INET;
	src.sin_family = AF_INET;
	dst.sin_addr.s_addr = inet_addr(inet_ntoa(((struct sockaddr_in*)dest->ai_addr)->sin_addr));
	if (input.source_ip)
		src.sin_addr.s_addr = inet_addr(input.source_addr);
	else
		src.sin_addr.s_addr = inet_addr(_interface_ip(input.interface_name, IPPROTO_TCP));

	SType	scan_types[input.num_of_scans];
	SType	*ss = scan_types;

	if (!prepare_configuration(&input, ss, dest, src))
		return	1;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, exit);

	Scan		scans[input.total_ports];
	Worker		workers[input.num_of_threads];
	memset(workers, 0, sizeof(workers));
	memset(scans, 0, sizeof(scans));

	if  (DEBUG)
		printf("size: %i in %li, scans: %p -> %p:%li\n",
		sizeof(Scan) * input.total_ports, sizeof(Scan), scans, scans + input.total_ports, sizeof(scans));

	bool		check_lock_mutex = false;
	Scan		*pseudo_scan_struct = scans;
	clock_t		_s_time = clock();

	for (int cur_port = input.min_port, cur_thread = 0; cur_port <= input.max_port;) {

		if (!workers[cur_thread].alive) workers[cur_thread].t_status = INIT;
		else {
			pthread_mutex_lock(&workers[cur_thread].mx);
			check_lock_mutex = true;
		}

		if (workers[cur_thread].t_status == INIT || workers[cur_thread].t_status == FINISH) {
			if (!workers[cur_thread].id)
				workers[cur_thread].id = (cur_port - input.min_port + 1) * 10 + random_num();
			workers[cur_thread].t_status = WAITING;
			workers[cur_thread].input = &input;
		}

		if (workers[cur_thread].t_status == WAITING) {
			workers[cur_thread].scan_start = pseudo_scan_struct;
			workers[cur_thread].scan_end = pseudo_scan_struct + 1;
			memcpy(&pseudo_scan_struct->dst, &dst, sizeof(dst));
			memcpy(&pseudo_scan_struct->src, &src, sizeof(src));
			memcpy(pseudo_scan_struct->_scan_types, scan_types, sizeof(scan_types));
			pseudo_scan_struct->num_of_types = sizeof(scan_types) / sizeof(SType);
			pseudo_scan_struct->port = cur_port;
			workers[cur_thread].t_status = RUNNING;
			if (!workers[cur_thread].alive) {
				pthread_mutex_init(&workers[cur_thread].mx, NULL);
				pthread_create(&workers[cur_thread].thread, NULL, _scan_routine, &workers[cur_thread]);
				workers[cur_thread].alive = true;
			}
			if (DEBUG) printf("####thread:%i#### given %p -> %p [%li], in boudaries? %i\n",
					workers[cur_thread].id, workers[cur_thread].scan_start, workers[cur_thread].scan_end,
					workers[cur_thread].scan_end - workers[cur_thread].scan_start,
					workers[cur_thread].scan_end > scans && workers[cur_thread].scan_end < scans + input.total_ports);
			pseudo_scan_struct += 1;
			cur_port++;
		}

		if (check_lock_mutex) {
			pthread_mutex_unlock(&workers[cur_thread].mx);
			check_lock_mutex = false;
		}

		cur_thread++;
		if (cur_thread >= input.num_of_threads) cur_thread = 0;
	}

	for (int i = 0; i < input.num_of_threads; i++) {
		pthread_join(workers[i].thread, NULL);
		pthread_detach(workers[i].thread);
		pthread_mutex_destroy(&workers[i].mx);
	}

	freeaddrinfo(dest);

	print_results(scans, input.total_ports, inet_ntoa(((struct sockaddr_in*)dest->ai_addr)->sin_addr), _s_time);
}

