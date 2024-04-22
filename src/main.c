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
#include "strbldr.h"
#include <ctype.h>
#include <getopt.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Filtering options structure.
typedef struct {
  bool tcp;   // TCP filter flag.
  bool udp;   // UDP filter flag.
  bool arp;   // ARP filter flag.
  bool icmp4; // ICMPv4 filter flag.
  bool icmp6; // ICMPv6 filter flag.
  bool igmp;  // IGMP filter flag.
  bool mld;   // MLD filter flag.
  bool ndp;   // NDP filter flag.
} filter_t;

// Print a list of available network interfaces.
void list_interfaces() {
  pcap_if_t *alldevsp = NULL;
  char *errbuf = NULL;

  if (pcap_findalldevs(&alldevsp, errbuf)) {
    fprintf(stderr, "%s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  for (pcap_if_t *devsp = alldevsp; devsp != NULL; devsp = devsp->next)
    printf("%s\n", devsp->name);

  pcap_freealldevs(alldevsp);
}

// Check if given interface can be opened with pcap_create().
// Return true if interface is valid, otherwise return false.
bool validate_interface(char *interface) {
  pcap_if_t *alldevs = NULL;
  char *errbuf = NULL;

  if (pcap_findalldevs(&alldevs, errbuf)) {
    fprintf(stderr, "%s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  bool found = 0;
  for (pcap_if_t *devs = alldevs; devs != NULL; devs = devs->next) {
    found = strcmp(interface, devs->name) == 0;
    if (found)
      break;
  }

  return found;
}

// Print usage instructions
void print_help(char *name) {
  printf("Usage: %s [-i interface | --interface interface] "
         "{-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} "
         "[--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n",
         name);
}

char *build_filter_string(filter_t *f) {
  sb_t sb = sb_create();

  if (f->tcp)
    sb_append_string(&sb, "tcp");

  if (f->udp) {
    if (f->tcp)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "udp");
  }

  if (f->arp) {
    if (f->tcp || f->udp)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "arp");
  }

  if (f->icmp4) {
    if (f->tcp || f->udp || f->arp)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "icmp");
  }

  if (f->icmp6) {
    if (f->tcp || f->udp || f->arp || f->icmp4)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "icmp6");
  }

  if (f->igmp) {
    if (f->tcp || f->udp || f->arp || f->icmp4 || f->icmp6)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "igmp");
  }

  if (f->mld) {
    if (f->tcp || f->udp || f->arp || f->icmp4 || f->icmp6 || f->igmp)
      sb_append_string(&sb, " or ");
    sb_append_string(&sb, "icmp6[icmp6type] = 130 or icmp6[icmp6type] = 131 or "
                          "icmp6[icmp6type] = 143 or icmp6[icmp6type] = 132");
  }

  if (f->ndp) {
    if (f->tcp || f->udp || f->arp || f->icmp4 || f->icmp6 || f->igmp || f->mld)
      sb_append_string(&sb, " or ");
    sb_append_string(
        &sb,
        "icmp6[icmp6type] = 133 or icmp6[icmp6type] = 134 or icmp6[icmp6type] "
        "= 135 or icmp6[icmp6type] = 136 or icmp6[icmp6type] = 137");
  }

  char *str = sb_get_string(sb);

  sb_destroy(sb);

  return str;
}

int main(int argc, char *argv[]) {
  char *interface = NULL;    // Selected interface.
  int port = -1;             // Port number to filter for.
  filter_t filter = {false}; // Filter options.
  int limit = 1;             // Number of results.

  // If there's no option specified, list available interfaces.
  if (argc == 1) {
    list_interfaces();
    return EXIT_SUCCESS;
  }

  // If there's only interface with no value specified, list available.
  // interfaces.
  if (argc == 2 &&
      (strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0)) {
    list_interfaces();
    return EXIT_SUCCESS;
  }

  // Definition of available long options.
  static const struct option long_options[] = {
      {"help",      no_argument,       NULL, 'h'},
      {"interface", required_argument, NULL, 'i'},
      {"port",      required_argument, NULL, 'p'},
      {"tcp",       no_argument,       NULL, 't'},
      {"udp",       no_argument,       NULL, 'u'},
      {"arp",       no_argument,       0,    0  },
      {"icmp4",     no_argument,       0,    0  },
      {"icmp6",     no_argument,       0,    0  },
      {"igmp",      no_argument,       0,    0  },
      {"mld",       no_argument,       0,    0  },
      {"ndp",       no_argument,       0,    0  },
      {0,           0,                 0,    0  },
  };

  // Parse options using getopt_long.
  int option_index = 0;
  for (int c; (c = getopt_long(argc, argv, "hi:p:tu012345n:", long_options,
                               &option_index)) != -1;) {
    switch (c) {
    case 'h':
      print_help(argv[0]);
      break;
    case 'i':
      if (!validate_interface(optarg)) {
        fprintf(stderr, "Invalid argument for option -i/--interface. (%s)\n",
                optarg);
      }
      interface = optarg;
      break;
    case 'p':
      long tmp_port = strtol(optarg, NULL, 10);
      if (!tmp_port) {
        fprintf(stderr, "Port must be a number. '%s' given.\n", optarg);
        return EXIT_FAILURE;
      }
      port = (int)tmp_port;
      break;
    case 't':
      filter.tcp = true;
      break;
    case 'u':
      filter.udp = true;
      break;
    case '0':
      filter.arp = true;
      break;
    case '1':
      filter.icmp4 = true;
      break;
    case '2':
      filter.icmp6 = true;
      break;
    case '3':
      filter.igmp = true;
      break;
    case '4':
      filter.mld = true;
      break;
    case '5':
      filter.ndp = true;
      break;
    case 'n':
      long tmp_limit = strtol(optarg, NULL, 10);
      if (!tmp_limit) {
        fprintf(stderr, "Option n argument must be a number. '%s' given.\n",
                optarg);
        return EXIT_FAILURE;
      }
      limit = (int)tmp_limit;
      break;
    case '?':
      if (isprint(optopt))
        fprintf(stderr, "Unknown option '-%c'.\n", optopt);
      else
        fprintf(stderr, "Unknown option `\\x%x'.\n", optopt);
      return EXIT_FAILURE;
    default:
      break;
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 net;
  bpf_u_int32 mask;
  struct bpf_program fp;

  if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", interface);
    net = 0;
    mask = 0;
  }

  // Obtain a packet capture handle.
  // https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
  pcap_t *handle = pcap_open_live(interface, 262144, 1, 0, errbuf);

  // Check if handle was obtained successfully, if not print error.
  if (handle == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    return EXIT_FAILURE;
  }

  char *filter_string = build_filter_string(&filter);

  printf("%s\n", filter_string);

  if (pcap_compile(handle, &fp, filter_string, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_string,
            pcap_geterr(handle));
    return EXIT_FAILURE;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_string,
            pcap_geterr(handle));
    return EXIT_FAILURE;
  }

  pcap_loop(handle, limit, print_packet, NULL);

  return EXIT_SUCCESS;
}
