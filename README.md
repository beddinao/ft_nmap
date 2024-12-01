# *`FT_NMAP`*

## key features
- initial ICMP ping: Prior to port scanning, the tool performs an ICMP ping to verify host connectivity.
- Nmap-like scans: Perform SYN, ACK, FIN, NULL, XMAS, and UDP scans to identify open ports and running services.
- Custom TCP flags: Customize scan behavior by specifying custom TCP flag combinations using the --flags option.
- Service detection: Attempts to identify potential services by comparing ports and transport protocols to the Service Name and Transport Protocol Port Number Registry.
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
## options
```
--help          prints this help screen and exit
--verbose       display incoming/outgoing packets
--scan          one or multiple scans: SYN | NULL | FIN | XMAS | ACK | UDP
                dafault: all
--flags         custom scan by setting the tcp flags header manually [syn, ack, rst, fin, psh, urg]
                example: --flags syn ack
--source-ip     source ip address to use
                this options disables looking up an interface address
                responses from target will come to this one
--source-port   source port to use
                default: random
--seq           tcp header: sequence number
                default: random
--ack-seq       tcp header: acknowledgment number
                default: 0
--speedup       number of parallel threads to use
                max: 255
                default: number of threads == number of ports
--interface     name of the interface to use
                default: enp0s3
                mandatory if this interface is not present/active
```
## example output
```
$ ft_nmap --scan SYN ACK scanme.nmap.org 80-90

Configurations:
Target Ip-Address: 45.33.32.156
Source Ip-Address: x.x.x.x
Using Interface: enp0s3
......................
icmp_echo request sent..
icmp_echoreply echo.id=64936, icmp_seq=65
Host State: Up
......................
No of Ports to scan: 11
No of threads: 11
Using known services database: database/services
Scans to be performed: SYN ACK 
Scanning...
......................
Scan took 0.015029 secs
IP address: 45.33.32.156

Open ports:
Port       Service Name (if applicable)     Results                              [Conclusion]

80         http                             SYN(Open) ACK(Unfiltered)            [Open]


Closed/Filtered/Unfiltered ports:
Port       Service Name (if applicable)     Results                              [Conclusion]

81         hosts2-ns                        SYN(Closed) ACK(Unfiltered)          [Closed]

82         xfer                             SYN(Closed) ACK(Unfiltered)          [Closed]

83         mit-ml-dev                       SYN(Closed) ACK(Unfiltered)          [Closed]

84         ctf                              SYN(Closed) ACK(Unfiltered)          [Closed]

85         mit-ml-dev                       SYN(Closed) ACK(Unfiltered)          [Closed]

86         mfcobol                          SYN(Closed) ACK(Unfiltered)          [Closed]

87         priv-term-l                      SYN(Closed) ACK(Unfiltered)          [Closed]

88         kerberos-sec                     SYN(Closed) ACK(Unfiltered)          [Closed]

89         su-mit-tg                        SYN(Closed) ACK(Unfiltered)          [Closed]

90         dnsix                            SYN(Closed) ACK(Unfiltered)          [Closed]


```

## upcoming features
- OS fingerprinting: Attempt to identify the operating system of the target host.
- Simplified Version detection: Attempts to Identify the versions of running services on some open ports.
- Configuration file for multiple host scanning
