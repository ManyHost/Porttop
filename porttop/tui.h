#ifndef TUI_H
#define TUI_H

#include "ports.h"

typedef struct {
    int selected;
    int offset;
    char search[64];
    int search_mode;   /* 1 = modal search active */
} ui_state_t;

void tui_init(void);
void tui_draw(port_entry_t *list, int count, ui_state_t *ui, int show_risk);
void tui_search(ui_state_t *ui);
int tui_confirm_kill(const port_entry_t *e);

#endif

