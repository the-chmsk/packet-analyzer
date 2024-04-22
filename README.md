# packet-analyzer

Simple packet analyzer in C.

## Description

A packet analyzer, commonly referred to as a network sniffer, is a tool used to capture and analyze network traffic. This implementation is based on the `libpcap` library, which enables it to listen and capture packets on any available network interface.

## Usage
This program accepts following options:

 - `-i / --inteface [network interface]` Display packets on given interface. If interface is empty, a list of available interfaces will be displayed.
 -  `-t / --tcp`Dispaly only TCP packets.
 -  `-u / --udp` Display only UDP packets.
 -  `-p [port]` Used with TCP or UDP. Display only packets with specified destination or source port.
 - `--port-destination` Used with TCP or UDP. Display only packets with specified destination port.
 -  `--port-source` Used with TCP or UDP. Display only packets with specified source port.
 -  `--icmp4` Display only ICMPv4 packets.
 -  `--icmp6` Display only ICMPv6 packets.
 -  `--ndp` Display only NDP packets.
 -  `--igmp` Display only IGMP packets.
 -  `--mld` Display only MLD packets.
 -  `-n [number of packets]` Dispaly specified number of packets. Default is 1.

If no interface is specified, program will print a list of the available interfaces.

## Build

To build this tool, ensure that you have `libpcap` installed.
Run `make`

## Tests

This program was tested manually by comparing output with `Wireshark` output. Automatic tests are planned, but due to complicated nature of packet analyzer, it was not done yet.  

### Testing scenario

Run program with desired options with option `- n -1`. This will make it run indefinitely. Open `Wireshark`, start listening on same interface as the program and apply same filters.  Wait until both programs start capturing same packets. Now compare program output with `Wireshark` as shown in following example.
![testing scneario](https://github.com/the-chmsk/packet-analyzer/blob/main/resources/test-scenario.png)
## BIbliography

[RFC9293] Eddy, W. _Transmission Control Protocol (TCP)_ [online]. August 2022. [cited 2024-02-11]. DOI: 10.17487/RFC9293. Available at: https://datatracker.ietf.org/doc/html/rfc9293

[RFC894] Hornig, C. _A Standard for the Transmission of IP Datagrams over Ethernet Networks_ [online]. April 1984. [cited 2024-02-14]. DOI: 10.17487/RFC894. Available at: https://datatracker.ietf.org/doc/html/rfc894

[RFC791] Information Sciences Institute, University of Southern California. _Internet Protocol_ [online]. September 1981. [cited 2024-02-14]. DOI: 10.17487/RFC791. Available at: https://datatracker.ietf.org/doc/html/rfc791

[RFC768] Postel, J. _User Datagram Protocol_ [online]. March 1997. [cited 2024-02-11]. DOI: 10.17487/RFC0768. Available at: https://datatracker.ietf.org/doc/html/rfc768
