#include "display/terminal.h"
#include "display/printk.h"
#include "limine.h"

#define TERMINAL_GOP
#define TERMINAL_EMBEDDED_FONT
#include "libs/os_terminal.h"

extern struct limine_framebuffer *framebuffer;

bool use_terminal = false;

void init_terminal() {
    TerminalDisplay display = {
        .width = framebuffer->width,
        .height = framebuffer->height,
        .address = framebuffer->address,
    };

    terminal_init(&display, 10.0, kalloc, kfree, NULL);
    terminal_print("\033[1;32mTerminal init!\033[0m\n");
    use_terminal = true;
}

void terminal_print(const char *buf) { terminal_advance_state(buf); }
