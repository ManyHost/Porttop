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
                    strncpy(proc, "?", 63);
                    proc[62] = '\0';
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
        if (sscanf(colon + 1, "%X", &port) != 1) continue;

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

/*
 * Cross-platform lsof-based parser for systems without /proc/net
 */
static void parse_lsof(port_entry_t *list, int max, const char *filter, int *idx)
{
    FILE *f = popen("lsof -i -n -P -FpcuTn", "r");
    if (!f) return;

    char line[512];
    // Skip header
    if (!fgets(line, sizeof(line), f)) {
        pclose(f);
        return;
    }

    port_entry_t temp = {0};
    while (fgets(line, sizeof(line), f) && *idx < max) {
        if (line[0] == 'p') {
            temp.pid = atoi(line+1);
        } else if (line[0] == 'c') {
            strncpy(temp.proc, line+1, sizeof(temp.proc)-1);
            temp.proc[sizeof(temp.proc)-1] = '\0';
        } else if (line[0] == 'u') {
            strncpy(temp.proto, "UDP", sizeof(temp.proto)-1);
            temp.proto[sizeof(temp.proto)-1] = '\0';
        } else if (line[0] == 'T') {
            if (strstr(line, "TCP")) {
                strncpy(temp.proto, "TCP", sizeof(temp.proto)-1);
                temp.proto[sizeof(temp.proto)-1] = '\0';
            }
        } else if (line[0] == 'n') {
            char *colon = strrchr(line+1, ':');
            if (colon) {
                temp.port = atoi(colon+1);
                size_t addr_len = colon - (line+1);
                if (addr_len >= sizeof(temp.addr)) addr_len = sizeof(temp.addr)-1;
                strncpy(temp.addr, line+1, addr_len);
                temp.addr[addr_len] = '\0';
            } else {
                strncpy(temp.addr, line+1, sizeof(temp.addr)-1);
                temp.addr[sizeof(temp.addr)-1] = '\0';
            }
            // Only add if proto and port are set
            if (temp.port > 0 && temp.proto[0]) {
                port_entry_t *e = &list[*idx];
                *e = temp;
                if (filter) {
                    char pbuf[16];
                    snprintf(pbuf, sizeof(pbuf), "%d", temp.port);
                    if (!strstr(e->proc, filter) && !strstr(pbuf, filter)) continue;
                }
                (*idx)++;
            }
            memset(&temp, 0, sizeof(temp));
        }
    }
}

int load_ports(port_entry_t *list, int max, const char *filter)
{
    int idx = 0;
    // macOS: always use lsof parser
    parse_lsof(list, max, filter, &idx);
    return idx;
}

