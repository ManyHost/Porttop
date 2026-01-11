#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#include "ports.h"
#include "util.h"

/*
 * EXACT inode → PID mapping
 */
static int inode_to_pid(const char *inode, char *proc)
{
    DIR *procdir = opendir("/proc");
    if (!procdir) return -1;

    char needle[64];
    snprintf(needle, sizeof(needle), "socket:[%s]", inode);

    struct dirent *pde;
    while ((pde = readdir(procdir))) {
        if (!isdigit(pde->d_name[0])) continue;

        char fdpath[256];
        snprintf(fdpath, sizeof(fdpath), "/proc/%s/fd", pde->d_name);
        DIR *fddir = opendir(fdpath);
        if (!fddir) continue;

        struct dirent *fde;
        while ((fde = readdir(fddir))) {
            char link[256], target[256];
            snprintf(link, sizeof(link), "%s/%s", fdpath, fde->d_name);

            ssize_t len = readlink(link, target, sizeof(target) - 1);
            if (len < 0) continue;
            target[len] = '\0';

            if (strcmp(target, needle) == 0) {
                char commpath[256];
                snprintf(commpath, sizeof(commpath),
                         "/proc/%s/comm", pde->d_name);

                FILE *f = fopen(commpath, "r");
                if (f) {
                    fgets(proc, 63, f);
                    proc[strcspn(proc, "\n")] = 0;
                    fclose(f);
                } else {
                    strcpy(proc, "?");
                }

                closedir(fddir);
                closedir(procdir);
                return atoi(pde->d_name);
            }
        }
        closedir(fddir);
    }

    closedir(procdir);
    return -1;
}

/*
 * ROBUST /proc/net parser using tokenization
 */
static void parse_net(const char *path, const char *proto,
                      port_entry_t *list, int max,
                      const char *filter, int *idx)
{
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    fgets(line, sizeof(line), f); // skip header

    while (fgets(line, sizeof(line), f) && *idx < max) {
        char *fields[32];
        int nf = 0;

        char *tok = strtok(line, " \t\n");
        while (tok && nf < 32) {
            fields[nf++] = tok;
            tok = strtok(NULL, " \t\n");
        }

        if (nf < 10)
            continue;

        /*
         * fields[1] = local_address (IP:PORT)
         * fields[9] = inode
         */
        char *local = fields[1];
        char *inode = fields[9];

        char *colon = strchr(local, ':');
        if (!colon) continue;

        *colon = '\0';

        unsigned int port;
        sscanf(colon + 1, "%X", &port);

        port_entry_t *e = &list[*idx];
        memset(e, 0, sizeof(*e));

        e->port = port;
        strncpy(e->proto, proto, sizeof(e->proto) - 1);
        hex_to_ip(local, e->addr);

        e->pid = inode_to_pid(inode, e->proc);
        if (e->pid < 0)
            continue;

        if (filter) {
            char pbuf[16];
            snprintf(pbuf, sizeof(pbuf), "%d", port);
            if (!strstr(e->proc, filter) &&
                !strstr(pbuf, filter))
                continue;
        }

        (*idx)++;
    }

    fclose(f);
}

int load_ports(port_entry_t *list, int max, const char *filter)
{
    int idx = 0;
    parse_net("/proc/net/tcp", "tcp", list, max, filter, &idx);
    parse_net("/proc/net/udp", "udp", list, max, filter, &idx);
    return idx;
}

