#include <ncurses.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "tui.h"

#define MIN_COLS 80
#define MIN_LINES 10

void tui_init(void)
{
    initscr();
    noecho();
    cbreak();
    keypad(stdscr, TRUE);
    mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, NULL);
    curs_set(0);
    timeout(200);
}

/* ---------- kill confirmation popup ---------- */

int tui_confirm_kill(const port_entry_t *e)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    if (cols < MIN_COLS || rows < MIN_LINES)
        return 0;

    int w = (cols > 70) ? 70 : cols - 4;
    int h = 9;
    int y = (rows - h) / 2;
    int x = (cols - w) / 2;

    WINDOW *win = newwin(h, w, y, x);
    keypad(win, TRUE);
    box(win, '|', '-');

    char info[128];
    snprintf(info, sizeof(info),
             "Port %d | PID %d | %s",
             e->port, e->pid, e->proc);

    mvwprintw(win, 1, (w - 13) / 2, "CONFIRM ACTION");
    mvwprintw(win, 3, (w - 36) / 2,
              "Are you sure you want to kill this port?");
    mvwprintw(win, 4, (w - strlen(info)) / 2, "%s", info);
    mvwprintw(win, 6, (w - 29) / 2,
              "^Y = Yes    ^N = No    ESC = No");

    wrefresh(win);

    while (1) {
        int ch = wgetch(win);
        if (ch == 25) { delwin(win); return 1; }
        if (ch == 14 || ch == 27) { delwin(win); return 0; }
    }
}

/* ---------- draw ---------- */

void tui_draw(port_entry_t *list, int count, ui_state_t *ui, int show_risk)
{
    (void)show_risk;

    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    if (cols < MIN_COLS || rows < MIN_LINES) {
        erase();
        mvprintw(rows/2 - 1, (cols - 17)/2, "Terminal too small");
        mvprintw(rows/2,     (cols - 23)/2,
                 "Current size : %d x %d", cols, rows);
        mvprintw(rows/2 + 1, (cols - 24)/2,
                 "Minimum size : %d x %d", MIN_COLS, MIN_LINES);
        mvprintw(rows/2 + 3, (cols - 19)/2, "Resize to continue");
        refresh();
        return;
    }

    erase();

    uid_t uid = geteuid();
    const char *user = (uid == 0) ? "root" : getpwuid(uid)->pw_name;

    if (ui->search_mode) {
        mvprintw(0, 0,
            "PORTTOP [SEARCH MODE: %s]  ^C exit search  q quit",
            ui->search);
    } else {
        mvprintw(0, 0,
            "PORTTOP  Running as: %s   ↑↓ scroll  ^K kill  ^W search  q quit",
            user);
    }

    int start_row = 1;
    int max_rows = rows - start_row - 1;

    if (ui->selected >= count)
        ui->selected = count ? count - 1 : 0;

    for (int i = 0; i < max_rows && i + ui->offset < count; i++) {
        int idx = i + ui->offset;
        if (idx == ui->selected) attron(A_REVERSE);

        mvprintw(start_row + i, 0,
            "%-5d %-3s %-15s %-6d %-12s",
            list[idx].port,
            list[idx].proto,
            list[idx].addr,
            list[idx].pid,
            list[idx].proc);

        if (idx == ui->selected) attroff(A_REVERSE);
    }

    refresh();
}

/* ---------- modal search ---------- */

void tui_search(ui_state_t *ui)
{
    timeout(-1); /* blocking input */

    echo();
    curs_set(1);

    mvprintw(LINES - 1, 0,
             "Search (modal, exits with ^C): ");
    clrtoeol();

    getnstr(ui->search, sizeof(ui->search) - 1);

    noecho();
    curs_set(0);

    ui->search_mode = 1;
    ui->selected = 0;
    ui->offset = 0;

    timeout(200);
}
