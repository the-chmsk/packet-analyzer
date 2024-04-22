/*
 * This file is part of packet-analyzer.
 *
 * Copyright (C) 2024  Oliver Ulrich
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "printer.h"

#define SIZE_ETHERNET 14 // Ethernet headers are always exactly 14 bytes.

#define ETH_ADDR_LEN 6
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806 // Ethernet ARP type.

#define ARP_HW_ADDR_LEN 6
#define ARP_IP_ADDR_LEN 4

#define IP_RF 0x8000      // Reserved fragment flag.
#define IP_DF 0x4000      // Dont fragment flag.
#define IP_MF 0x2000      // More fragments flags.
#define IP_OFFMASK 0x1fff // Mask for fragmenting bits.

#define IP_HL(ip) ((ip->vhl) & 0x0f)
#define IP_V(ip) ((ip->vhl) >> 4)

#define TH_OFF(th) ((th->offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)

typedef unsigned int tcp_seq;

struct __attribute__((packed)) header_ethernet {
  uint8_t dhost[ETH_ADDR_LEN]; // Destination host address.
  uint8_t shost[ETH_ADDR_LEN]; // Source host address.
  uint16_t type;               // IP? ARP? RARP? etc.
};

struct __attribute__((packed)) header_arp {
  uint16_t htype;               // Hardware type.
  uint16_t ptype;               // Protocol type.
  uint8_t halen;                // Hardware address length.
  uint8_t palen;                // Protocol address length.
  uint16_t opcode;              // Operation code.
  uint8_t sha[ARP_HW_ADDR_LEN]; // Sender hardware address.
  uint8_t sia[ARP_IP_ADDR_LEN]; // Sender IP address.
  uint8_t tha[ARP_HW_ADDR_LEN]; // Target hardware address.
  uint8_t tia[ARP_IP_ADDR_LEN]; // Target IP address.
};

struct header_ip {
  unsigned char vhl;  // Version << 4 || header length >> 2.
  unsigned char tos;  // Type of service.
  unsigned short len; // Total length.
  unsigned short id;  // Identification.
  unsigned short off; // Fragment offset field.
  unsigned char ttl;  // Time to live.
  unsigned char prot; // Protocol.
  unsigned short sum; // Checksum.
  struct in_addr src; // Source address.
  struct in_addr dst; // Destination address.
};

struct header_tcp {
  unsigned short sport; // Source port.
  unsigned short dport; // Destination port.
  tcp_seq seq;          // Sequence number.
  tcp_seq ack;          // Acknowledgement number.
  unsigned char offx2;  // Data offset rsvd.
  unsigned char flags;  // Flags.
  unsigned short win;   // Window.
  unsigned short sum;   // Checksum.
  unsigned short urp;   // Urgent pointer.
};

// Format time in ISO8601 format.
void print_timestamp(const struct timeval *tv) {
  char buf[31];
  struct tm tm;

  // Convert time to "struct tm".
  localtime_r(&tv->tv_sec, &tm);

  // Since strftime can't do subsecond precision, we must hack it using
  // workaround.
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.%%03ld%z", &tm);

  printf("timestamp: ");

  // Replace %03ld with useconds.
  printf(buf, tv->tv_usec / 1000);

  printf("\n");
}

void print_ethernet(const struct header_ethernet *eth) {
  printf("Ethernet II:\n");

  // Print formatted mac addresses.
  printf("src MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->shost[0],
         eth->shost[1], eth->shost[2], eth->shost[3], eth->shost[4],
         eth->shost[5]);
  printf("dst MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->dhost[0],
         eth->dhost[1], eth->dhost[2], eth->dhost[3], eth->dhost[4],
         eth->dhost[5]);
  printf("type: 0x%04x\n", eth->type);

  printf("\n");
}

// Print IP header data.
void print_ip(const struct header_ip *ip) {
  printf("src IP: %s\n", inet_ntoa(ip->src));
  printf("dst IP: %s\n", inet_ntoa(ip->dst));
}

void print_tcp(const struct header_tcp *tcp) {
  printf("src port: %hu\n", tcp->sport);
  printf("dst port: %hu\n", tcp->dport);
}

// Print frame in "byte_offset: byte_offset_hexa byte_offset_ascii" format.
void print_frame(const unsigned char *packet, size_t size) {
  for (size_t offset = 0; offset < size; offset += 0x10) {
    printf("0x%04lX:  ", offset);

    for (size_t i = 0; i < 0x10; i++) {
      if (offset + i > size) {
        printf("   ");
        continue;
      }

      printf(" %02x", (unsigned int)*(packet + offset + i));
      if (i == 0x7)
        printf(" ");
    }

    printf("   ");

    for (size_t i = 0; i < 0x10; i++) {

      if (offset + i > size) {
        printf(" ");
        continue;
      }

      unsigned char c = *(packet + offset + i);

      if (!isprint(c))
        c = '.';

      printf("%c", c);
      if (i == 0x7)
        printf(" ");
    }

    printf("\n");
  }
}

void print_arp(struct header_arp *arp) {
  printf("Address Resolution Protocol (ARP Probe)\n");
  printf("hardware type: %u\n", arp->htype);
}

void print_packet(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet) {
  struct header_ethernet *eth = (struct header_ethernet *)(packet);

  print_timestamp(&header->ts);
  print_ethernet(eth);

  if (eth->type == ETH_TYPE_ARP) {
    print_arp((struct header_arp *)(packet + SIZE_ETHERNET));
  } else if (eth->type == ETH_TYPE_IP) {
    const struct header_ip *ip = (struct header_ip *)(packet + SIZE_ETHERNET);

    unsigned int size_ip = IP_HL(ip) * 4;

    print_ip(ip);

    switch (ip->prot) {
    case IPPROTO_TCP:
      // Obtain and print TCP header.
      print_tcp((struct header_tcp *)(packet + SIZE_ETHERNET + size_ip));
      break;

    default:
      break;
    }
  }

  printf("\n");

  print_frame(packet, header->caplen);

  printf("\n");
}