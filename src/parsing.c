#include "ft_nmap.h"

bool	is_valid_ports(char *port, Options *input) {
	if (!port) return false;
	int	underscore = 0;
	int	min_port, max_port;

	for (int i = 0; port[i]; i++) {
		if (port[i] < '0' || port[i] > '9') {
			if (port[i] == '-' && !underscore
				&& i > 0 && port[i + 1])
				underscore = i;
			else	return false;
		}
	}

	min_port = atoi(port);
	if (!min_port || min_port < MIN_PORT_NUM || min_port > MAX_PORT_NUM)
		return false;

	if (underscore) {
		max_port = atoi(port + underscore + 1);
		if (!max_port || max_port < MIN_PORT_NUM || max_port > MAX_PORT_NUM)
			return false;
		if (min_port > max_port)
			return false;
	}
	else	max_port = min_port;

	if (max_port - min_port + 1 > MAX_PORTS) return false;

	input->min_port = min_port;
	input->max_port = max_port;

	return true;
}

bool	is_valid_target(char *target, Options *input) {
	if (!target) return false;
	int	size = strlen(target);

	if (size > MAX_TAR_LGH)
		return false;

	for (int i = 0; i < size; i++) {
		if (!isdigit(target[i])
			&& !isalpha(target[i])
			&& target[i] != '.' && target[i] != '-'
			&& target[i] != '_')
			return	false;
	}
	memcpy(&input->target, target, size);
	return	true;
}

bool	is_valid_scans(char **v, int *arg, int c, Options *input) {
	if (*arg + 1 > c - 2)	return	false;

	for (;*arg < c - 2; *arg += 1, input->num_of_scans += 1) {
		if (!strcmp(v[*arg], "SYN"))
			input->SYN = 1;
		else if (!strcmp(v[*arg], "NULL"))
			input->null = 1;
		else if (!strcmp(v[*arg], "FIN"))
			input->FIN = 1;
		else if (!strcmp(v[*arg], "XMAS"))
			input->XMAS = 1;
		else if (!strcmp(v[*arg], "ACK"))
			input->ACK = 1;
		else if (!strcmp(v[*arg], "UDP"))
			input->UDP = 1;
		else	break;
	}

	input->scans = true;
	return	true;
}

bool	is_valid_flags(char **v, int *arg, int c, Options *input) {
	if (*arg + 1 > c - 2)	return false;

	for (; *arg < c - 2; *arg += 1) {
		if (!strcmp(v[*arg], "syn"))
			input->f_syn = 1;
		else if (!strcmp(v[*arg], "ack"))
			input->f_ack = 1;
		else if (!strcmp(v[*arg], "rst"))
			input->f_rst = 1;
		else if (!strcmp(v[*arg], "fin"))
			input->f_fin = 1;
		else if (!strcmp(v[*arg], "psh"))
			input->f_psh = 1;
		else if (!strcmp(v[*arg], "urg"))
			input->f_urg = 1;
		else	break;
	}
	input->flags = 1;
	return true;
}

bool	is_valid_seq(char **v, int *arg, int c, Options *input) {
	if (*arg + 1 > c - 2)	return false;
	bool	is_ack_seq = strcmp(v[*arg - 1], "--ack_seq") == 0;
	int	number, size;

	size = strlen(v[*arg]);
	for (int i = 0; i < size; i++)
		if (!isdigit(v[*arg][i])) return false;

	if ( size == 1 && v[*arg][0] == '0')
		number = 0;
	else	number = atoi(v[*arg]);

	if (!is_ack_seq) {
		input->seq = 1;
		input->seq_num = number;
	}
	else {
		input->ack_seq = 1;
		input->ack_seq_num = number;
	}
	*arg += 1;
	return	true;
}

bool	is_valid_threads_num(char **v, int *arg, int c, Options *input) {
	if (*arg + 1 > c - 2)	return false;
	int	number, size;

	size = strlen(v[*arg]);
	for (int i = 0; i < size; i++)
		if (!isdigit(v[*arg][i]))	return false;

	if (size == 1 && v[*arg][0] == '0')
		number = 0;
	else	number = atoi(v[*arg]);

	if (number < 0 || number > MAX_THREADS) return false;

	*arg += 1;
	input->speedup = 1;
	input->num_of_threads = number;
	return	true;
}

bool	is_valid_interface(char **v, int *arg, int c, Options *input) {
	if (*arg + 1 > c - 2)	return false;

	int	size = strlen(v[*arg]);
	if (size > IFR_MAX_LGH)	return false;
	for (int i = 0; i < size; i++)
		if (v[*arg][i] == '/') return false;

	input->interface = true;
	memcpy(&input->interface_name, v[*arg], size);
	*arg += 1;
	return true;
}

void	parse_input(Options *input, char **v, int c) {
	input->valid = 1;

	for (int i = 1; i < c; i++)
		if (!strcmp("--help", v[i])) {
			input->help = 1;
			return ;
		}

	if (c < 3) {
		print_help(false);
		input->valid = 0;
		return ;
	}

	if (!is_valid_ports(v[c - 1], input)) {
		write(2, "invalid port number/range: ", 27);
		write(2, v[c - 1], strlen(v[c-1]));
		input->valid = 0;
		return;
	}

	if (!is_valid_target(v[c - 2], input)) {
		write(2, "invalid address: ", 17);
		write(2, v[c - 2], strlen(v[c - 2]));
		input->valid = 0;
		return;
	}

	if (c > 3) {
		int	arg = 1;
		for (; arg < c - 2;) {
			if (!strcmp(v[arg], "--verbose")) {
				input->verbose = 1;
				arg++;
			}
			else if (!strcmp(v[arg], "--scan")) {
				arg++;
				if (!is_valid_scans(v, &arg, c, input)) {
					write(2, "invalid scan: ", 14);
					input->valid = 0;
					break;
				}
			}
			else if (!strcmp(v[arg], "--flags")) {
				arg++;
				if (!is_valid_flags(v, &arg, c, input)) {
					write(2, "invalid flag: ", 14);
					input->valid = 0;
					break;
				}
			}
			else if (!strcmp(v[arg], "--seq") || !strcmp(v[arg], "--ack_seq")) {
				arg++;
				if (!is_valid_seq(v, &arg, c, input)) {
					write(2, "invalid sequence number: ", 25);
					input->valid = 0;
					break;
				}
			}
			else if (!strcmp(v[arg], "--speedup")) {
				arg++;
				if (!is_valid_threads_num(v, &arg, c, input))  {
					write(2, "invalid threads number: ", 24);
					input->valid = 0;
					break;
				}
			}
			else if (!strcmp(v[arg], "--interface")) {
				arg++;
				if (!is_valid_interface(v, &arg, c, input)) {
					write(2, "invalid interface name: ", 24);
					input->valid = 0;
					break;
				}
			}
			else {
				write(2, "invalid argument: ", 18);
				input->valid = 0;
				break;
			}
		}
		if (!input->valid)
			write(2, v[arg], strlen(v[arg]));
	}
	srand(time(NULL));
	if (input->flags) {
		input->num_of_scans += 1;
		input->CUST = 1;
	}
	
	if (!input->interface) {
		input->interface = 1;
		memcpy(&input->interface_name, INTERFACE, strlen(INTERFACE));
	}
	if (!input->scans && !input->flags) {
		input->scans = true;
		input->SYN = 1;
		input->ACK = 1;
		input->null = 1;
		input->FIN = 1;
		input->XMAS = 1;
		input->UDP = 1;
		input->num_of_scans = 6;
	}
	if (!input->seq) {
		input->seq = 1;
		input->seq_num = random_num();
	}
	if (!input->ack_seq) {
		input->ack_seq = 1;
		input->ack_seq_num = 0;
	}
	input->total_ports = input->max_port - input->min_port + 1;
	if (!input->speedup || input->num_of_threads > input->total_ports) {
		input->speedup = 1;
		input->num_of_threads = input->total_ports;
	}

}
