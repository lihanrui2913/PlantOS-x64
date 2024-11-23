#include "display/terminal.h"
#include "display/printk.h"
#include "limine.h"

#include "libs/os_terminal.h"

extern struct limine_framebuffer *framebuffer;

bool use_terminal = false;

void init_terminal()
{
    terminal_init(framebuffer->width, framebuffer->height, framebuffer->address, 11.0f, kalloc, kfree, NULL);
    terminal_print("\033[1;32mTerminal init!\033[0m\n");
    use_terminal = true;
}

void terminal_print(const char *buf) { terminal_advance_state(buf); }
