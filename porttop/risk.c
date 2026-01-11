#include <string.h>
#include "risk.h"
#include "util.h"

static int enabled = 0;

int load_risk_config(const char *path) {
    enabled = file_exists(path);
    return enabled;
}

void apply_risk_rules(port_entry_t *list, int count) {
    if (!enabled) return;

    for (int i = 0; i < count; i++) {
        if (list[i].port == 22) {
            list[i].has_risk = 1;
            strcpy(list[i].risk, "HIGH");
            strcpy(list[i].reason, "SSH exposed");
        }
    }
}

