#ifndef PORTS_H
#define PORTS_H

#define MAX_PORTS 1024

typedef struct {
    int port;
    char proto[4];
    char addr[64];
    int pid;
    char proc[64];

    int has_risk;
    char risk[10];
    char reason[128];
} port_entry_t;

int load_ports(port_entry_t *list, int max, const char *filter);

#endif
