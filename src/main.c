#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



void list_interfaces() {
  // TODO: Print list of available interfaces
}

int main(int argc, char *argv[]) {

  // If thre's no option specified, list available interfaces.
  if (argc == 1)
    list_interfaces();

  // If there's only interface with no value specified, list available interfaces.
  if (argc == 2 && (strcmp("-i", argv[0]) == 0 || strcmp("--interface", argv[0]) == 0))
    list_interfaces();

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

  int option_index = 0;
  for (int c; (c = getopt_long(argc, argv, "hi:p:tu01234", long_options,
                               &option_index)) != -1;) {
    // TODO: Implement option parsing
  }

  return EXIT_SUCCESS;
}
