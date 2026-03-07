#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include "util.h"

void hex_to_ip(const char *hex, char *out) {
    unsigned int a,b,c,d;
    if (sscanf(hex, "%2X%2X%2X%2X", &d,&c,&b,&a) == 4) {
        sprintf(out, "%u.%u.%u.%u", a,b,c,d);
    } else {
        strcpy(out, "0.0.0.0");
    }
}

int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

void strlower(char *s) {
    for (; *s; s++)
        *s = tolower(*s);
}

