#include "ft_nmap.h"

void	print_response_packets(struct tcphdr *tcp_hdr, struct icmphdr *icmp_hdr, int port) {
	if (tcp_hdr)
		printf("<- TCP [%i] syn: %i | ack: %i | rst: %i | fin: %i | psh: %i | urg: %i | seq: %i | ack_seq: %i | window: %i\n",
		port, tcp_hdr->syn, tcp_hdr->ack, tcp_hdr->rst, tcp_hdr->fin, tcp_hdr->psh, tcp_hdr->urg,
		ntohl(tcp_hdr->seq), ntohl(tcp_hdr->ack_seq), ntohs(tcp_hdr->window));
	if (icmp_hdr)
		printf("<- ICMP [%i] type: %i | code: %i\n", port, icmp_hdr->type, icmp_hdr->code);
}

int	print_scan_type(char *bf, SType t, char *af) {
	char	name[5];
	int	len;

	memset(name, 0, 5);
	switch (t) {
		case SYN: len = 3; memcpy(name, "SYN", len); break;
		case ACK: len = 3; memcpy(name, "ACK", len); break;
		case FIN: len = 3; memcpy(name, "FIN", len); break;
		case XMAS: len = 4; memcpy(name, "XMAS", len); break;
		case UDP: len = 3; memcpy(name, "UDP", len); break;
		case null: len = 4; memcpy(name, "NULL", len); break;
		case CUST: len = 4; memcpy(name, "CUSTOM", len); break;
	}
	if (bf)	len += printf("%s", bf);
	printf("%s", name);
	if (af)	len += printf("%s", af);
	return	len;
}

int	print_port_status(char *bf, PStatus s, char *af) {
	char		name[16];
	int		len;

	memset(name, 0, 16);
	switch (s) {
		case FAILURE: len = 7; memcpy(name, "Failure", len); break;
		case OPEN: len = 4; memcpy(name, "Open", len); break;
		case CLOSED: len = 6; memcpy(name, "Closed", len); break;
		case FILTERED: len = 8; memcpy(name, "Filtered", len); break;
		case OPEN_FILTERED: len = 13; memcpy(name, "Open|Filtered", len); break;
		case CLOSED_FILTERED: len = 15; memcpy(name, "Closed|Filtered", len); break;
		case UNFILTERED: len = 10; memcpy(name, "Unfiltered", len); break;
		case SUCCESS: len = 7; memcpy(name, "Success", len); break;
		case NO_RESPONSE: len = 11; memcpy(name, "No Response", len); break;
	}
	if (bf)	len += printf("%s", bf);
	printf("%s", name);
	if (af)	len += printf("%s", af);
	return	len;
}

void	print_line(char ch, int width, char *c, char *c_e, bool n_l) {
	if (c)	printf("%s", c);
	for (int i = 0; i < width; i++)
		printf("%c", ch);
	if (c_e)	printf("%s", c_e);
	if (n_l)	printf("\n");
}

void	print_str_col(char *str, int size, int col_max_wid, bool n_l) {
	int	i = col_max_wid - size;
	printf("%s", str);
	if (i > 0) print_line(' ', i, NULL, NULL, n_l);
}

void	print_int_col(int n, int col_max_wid, bool n_l) {
	int	size = 0, sn = n, i;

	while (sn) {
		sn /= 10;
		size++;
	}
	i = col_max_wid - size;
	printf("%i", n);
	if (i > 0) print_line(' ', i, NULL, NULL, n_l);
}

void	print_ports_table(Scan *scans, int total_scans, char *title, bool is_open) {
	bool	title_there = false;
	int	col1_w = TERM_WIDTH / 10,
		col2_w = TERM_WIDTH / 3.3,
		col3_w = TERM_WIDTH / 2,
		col4_s;

	for (Scan *cur_scan = scans; cur_scan < scans + total_scans; cur_scan += 1) {
		if (is_open && cur_scan->conclusion != OPEN) continue;
		else if (!is_open && cur_scan->conclusion == OPEN) continue;

		if (!title_there) {
			printf("\n%s:\n", title);
			print_str_col("Port", 4, col1_w, false);
			print_str_col("Service Name (if applicable)", 28, col2_w, false);
			print_str_col("Results", 7, col3_w, false);
			printf("[Conclusion]\n");
			print_line(' ', TERM_WIDTH, WHTC, NRMC, true);
			title_there = true;
		}

		print_int_col(cur_scan->port, col1_w, false);
		print_str_col(cur_scan->service, strlen(cur_scan->service), col2_w, false);

		col4_s = 0;
		for (int cur_type = 0; cur_type < cur_scan->num_of_types; cur_type++) {
			col4_s += print_scan_type("", cur_scan->_scan_types[cur_type], "");
			col4_s += print_port_status("(", cur_scan->_scan_status[cur_type], ") ");
			if (cur_type && !((cur_type+1) % 2) && cur_type < cur_scan->num_of_types - 1) {
				print_line(' ', col1_w + col2_w, "\n", NULL, false);
				col4_s = 0;
			}
		}

		print_line(' ', col3_w - col4_s, NULL, NULL, false);
		print_port_status("[", cur_scan->conclusion, "]\n");
		if (cur_scan + 1 < scans + total_scans)
			print_line(' ', TERM_WIDTH, WHTC, NRMC, true);
	}
}

void	print_results(Scan *scans, int total_scans, char *addr, clock_t _s_time) {
	float	secs = 0;

	print_line('.', TERM_WIDTH / 5, NULL, NULL, true);
	printf("Scan took %f secs\n", (float)(clock() - _s_time) / CLOCKS_PER_SEC);
	printf("IP address: %s\n", addr);
	print_ports_table(scans, total_scans, "Open ports", true);
	print_ports_table(scans, total_scans, "Closed/Filtered/Unfiltered ports", false);
	printf("\n");
}

void	print_help(bool options) {
	int	f_col = TERM_WIDTH / 7;

	printf("\nusage:\n");

	printf("ft_nmap [OPTIONS] TARGET PORT(S)\n");
	print_line(' ', f_col, NULL, NULL, false);
	printf("target: ip address of the target host or its FQDN\n");
	print_line(' ', f_col, NULL, NULL, false);
	printf("ports: a single port number or a range in the syntax xx-xx\n");
	print_line(' ', f_col, NULL, NULL, false);
	printf("%i is the max number of ports\n", MAX_PORTS);

	if (options) {
		print_line(' ', f_col, NULL, NULL, false);
		printf("(you can adjust this in compilation using -D MAX_PORTS=N)\n");

		printf("\noptions:\n");
		print_str_col("--help", 6, f_col, false);
		printf("prints this help screen and exit\n");

		print_str_col("--verbose", 9, f_col, false);
		printf("display incoming/outgoing packets\n");

		print_str_col("--scan", 6, f_col, false);
		printf("one or multiple scans: SYN | NULL | FIN | XMAS | ACK | UDP\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("dafault: all\n");

		print_str_col("--flags", 7, f_col, false);
		printf("custom scan by setting the tcp flags header manually [syn, ack, rst, fin, psh, urg]\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("example: --flags syn ack\n");

		print_str_col("--seq", 5, f_col, false);
		printf("tcp header: sequence number\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("default: random\n");

		print_str_col("--ack_seq", 9, f_col, false);
		printf("tcp header: acknowledgment number\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("default: 0\n");

		print_str_col("--speedup", 9, f_col, false);
		printf("number of parallel threads to use\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("max: %i\n", MAX_THREADS);
		print_line(' ', f_col, NULL, NULL, false);
		printf("default: number of threads == number of ports\n");

		print_str_col("--interface", 11, f_col, false);
		printf("name of the interface to use\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("default: enp0s3\n");
		print_line(' ', f_col, NULL, NULL, false);
		printf("mandatory if this interface is not present/active\n");
	}
}

/*
void	print_input(Options *input) {
	printf("valid: %i\n", input->valid);
	printf("help: %i\n", input->help);
	printf("verbose: %i\n", input->verbose);
	printf("target: %s\n", input->target);
	printf("min_port: %i\n", input->min_port);
	printf("max_port: %i\n", input->max_port);
	printf("scans: %i\n", input->scans);
	printf("num_of_scans: %i\n", input->num_of_scans);
	printf("SYN: %i\n", input->SYN);
	printf("NULL: %i\n", input->null);
	printf("FIN: %i\n", input->FIN);
	printf("XMAS: %i\n", input->XMAS);
	printf("ACK: %i\n", input->ACK);
	printf("UDP: %i\n", input->UDP);
	printf("flags: %i\n", input->flags);
	printf("f_syn: %i\n", input->f_syn);
	printf("f_ack: %i\n", input->f_ack);
	printf("f_rst: %i\n", input->f_rst);
	printf("f_fin: %i\n", input->f_fin);
	printf("f_psh: %i\n", input->f_psh);
	printf("f_urg: %i\n", input->f_urg);
	printf("seq: %i\n", input->seq);
	printf("seq_num: %i\n", input->seq_num);
	printf("ack_seq: %i\n", input->ack_seq);
	printf("ack_seq_num: %i\n", input->ack_seq_num);
	printf("speedup: %i\n", input->speedup);
	printf("num_of_threads: %i\n", input->num_of_threads);
	printf("interface: %i\n", input->interface);
	printf("interface_name: %s\n", input->interface_name);
}

*/
