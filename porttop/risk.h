#ifndef RISK_H
#define RISK_H

#include "ports.h"

int load_risk_config(const char *path);
void apply_risk_rules(port_entry_t *list, int count);

#endif
