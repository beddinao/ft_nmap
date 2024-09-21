# FT_NMAP
## about
This project is a simple,
yet effective port scanning tool designed to help identify open ports on a target network or host. 
## requirements
- linux
- root privilege
## usage
```
$ ft_nmap [OPTIONS] TARGET PORT(S)
               target: ip address of the target host or its FQDN
               ports: a single port number or a range in the syntax xx-xx
               1024 is the max number of ports
```
## example
```
$ ft_nmap --scan SYN 192.168.1.100 80-443
```
This command will perform a SYN scan on host 192.168.1.100 for all ports from 80 to 443.
