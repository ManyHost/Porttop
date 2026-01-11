# Porttop

Porttop is a lightweight, terminal-based utility for viewing and managing
open network ports on Linux.

It provides a btop/htop-style TUI focused specifically on ports and the
processes that own them, with an emphasis on speed, safety, and SSH usability.

Porttop is designed for homelabs, servers, and power users who want a faster
and safer alternative to chaining together `ss`, `lsof`, and `kill`.

---

## What Porttop Does

- Lists open TCP and UDP ports
- Shows the process name and PID bound to each port
- Displays data in an interactive ncurses interface
- Allows safe killing of processes holding ports
- Works well over SSH and headless systems
- Has minimal dependencies

Porttop focuses on port management and avoids unnecessary complexity.

---

## What Porttop Is Not

- It is not a firewall
- It is not a packet sniffer
- It is not a full network analysis tool
- It does not replace `ss` or `lsof`

Porttop is intended as a convenience and safety tool for managing ports, not
as a deep inspection utility.

---
## Building from Source

To build Porttop from source, clone the repository and switch to the Stable branch:

```bash
git clone https://github.com/ManyHost/Porttop.git
cd Porttop
git checkout Stable

## Requirements

- Linux
- `/proc` filesystem
- `gcc`
- `make`
- ncurses development headers

Package examples:

```bash
sudo pacman -S ncurses
sudo apt install gcc make libncurses-dev
