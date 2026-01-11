#include <signal.h>
#include <ncurses.h>
#include "ports.h"
#include "tui.h"

int main(void)
{
    port_entry_t ports[MAX_PORTS];
    ui_state_t ui = {0};

    tui_init();

    while (1) {
        int count = load_ports(
            ports,
            MAX_PORTS,
            ui.search_mode ? ui.search : NULL
        );

        tui_draw(ports, count, &ui, 0);

        int ch = getch();
        if (ch == ERR)
            continue;

        if (ch == 'q')
            break;

        /* Ctrl+C exits search mode */
        if (ch == 3 && ui.search_mode) {
            ui.search_mode = 0;
            ui.search[0] = '\0';
            continue;
        }

        if (ch == 23 && !ui.search_mode) /* Ctrl+W */
            tui_search(&ui);

        if (ch == KEY_UP && ui.selected > 0)
            ui.selected--;

        if (ch == KEY_DOWN && ui.selected < count - 1)
            ui.selected++;

        /* ---------- MOUSE HANDLING ---------- */
        if (ch == KEY_MOUSE) {
            MEVENT ev;
            if (getmouse(&ev) == OK) {
                int list_start = 1;
                int row = ev.y - list_start + ui.offset;

                if (row >= 0 && row < count) {
                    ui.selected = row;

                    /* Right click = kill */
                    if (ev.bstate & BUTTON3_CLICKED) {
                        if (ports[ui.selected].pid > 1) {
                            if (tui_confirm_kill(&ports[ui.selected])) {
                                kill(ports[ui.selected].pid, SIGTERM);
                            }
                        }
                    }
                }
            }
        }

        /* Keyboard kill */
        if (ch == 11 && count > 0) { /* Ctrl+K */
            if (ports[ui.selected].pid > 1) {
                if (tui_confirm_kill(&ports[ui.selected])) {
                    kill(ports[ui.selected].pid, SIGTERM);
                }
            }
        }

        if (ui.selected < ui.offset)
            ui.offset = ui.selected;
        if (ui.selected >= ui.offset + LINES - 4)
            ui.offset = ui.selected - (LINES - 5);
    }

    endwin();
    return 0;
}
