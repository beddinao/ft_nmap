# FT_NMAP

## About
This project is a simple, yet effective port scanning tool designed to help identify open ports on a target network or host. Crafted in C for efficiency and portability, it offers a basic foundation for network exploration and security assessments.
## Key Features
- initial ICMP ping: Prior to port scanning, the tool performs an ICMP ping to verify host connectivity.
- Nmap-like scans: Perform SYN, ACK, FIN, NULL, XMAS, and UDP scans to identify open ports and running services.
- Custom TCP flags: Customize scan behavior by specifying custom TCP flag combinations using the --flags option.
- Service detection: Attempts to identify potential services by comparing ports and transport protocols to the Service Name and Transport Protocol Port Number Registry.
## Requirements
- linux
- root privilege
## Usage
```
$ ft_nmap [OPTIONS] TARGET PORT(S)
               target: ip address of the target host or its FQDN
               ports: a single port number or a range in the syntax xx-xx
               1024 is the max number of ports
```
## Options
```
--help         prints this help screen and exit
--verbose      display incoming/outgoing packets
--scan         one or multiple scans: SYN | NULL | FIN | XMAS | ACK | UDP
               dafault: all
--flags        custom scan by setting the tcp flags header manually [syn, ack, rst, fin, psh, urg]
               example: --flags syn ack
--seq          tcp header: sequence number
               default: random
--ack_seq      tcp header: acknowledgment number
               default: 0
--speedup      number of parallel threads to use
               max: 255
               default: number of threads == number of ports
--interface    name of the interface to use
               default: enp0s3
               mandatory if this interface is not present/active
```
## Example
```
$ ft_nmap --scan SYN 192.168.1.100 80-443
```
This command will perform a SYN scan
on host 192.168.1.100 for all ports from 80 to 443.

## Upcoming Features
- OS fingerprinting: Attempt to identify the operating system of the target host.
- Simplified Version scanning: Attempts to Identify the versions of running services on some open ports.
