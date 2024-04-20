#include <ctype.h>
#include <getopt.h>
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
} filter_t;

// Print a list of available network interfaces.
void list_interfaces() {
  // TODO: Print list of available interfaces
}

// Print usage instructions
void print_help(char *name) {
  printf("Usage: %s [-i interface | --interface interface] "
         "{-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} "
         "[--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n",
         name);
}

int main(int argc, char *argv[]) {
  char *interface = NULL; // Selected interface.
  int port = -1; // Port number to filter for.
  filter_t filter = {false}; // Filter options.
  int limit = 1;  // Number of results.

  // If there's no option specified, list available interfaces.
  if (argc == 1)
    list_interfaces();

  // If there's only interface with no value specified, list available.
  // interfaces.
  if (argc == 2 &&
      (strcmp("-i", argv[0]) == 0 || strcmp("--interface", argv[0]) == 0))
    list_interfaces();

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
      {0,           0,                 0,    0  },
  };

  // Parse options using getopt_long.
  int option_index = 0;
  for (int c; (c = getopt_long(argc, argv, "hi:p:tu01234n:", long_options,
                               &option_index)) != -1;) {
    switch (c) {
    case 'h':
      print_help(argv[0]);
      break;
    case 'i':
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
    case 'n':
      if (!optarg) {
        fprintf(stderr, "%s", optarg);
        return EXIT_FAILURE;
      }
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

  return EXIT_SUCCESS;
}
