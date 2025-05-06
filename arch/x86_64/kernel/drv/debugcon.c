#include "arch/pio.h"
#include "init/cmdline.h"
#include "sections.h"
#include "util/printk.h"
#include <stdbool.h>
#include <stddef.h>

#define DEBUGCON_PORT 0xe9

static void write_debugcon(printk_sink_t *self, const void *data, size_t count) {
    pio_write8_n(DEBUGCON_PORT, data, count);
}

INIT_TEXT static void init_debugcon(const char *name, char *value) {
    static printk_sink_t sink = {.write = write_debugcon};
    static bool initialized;

    if (initialized) return;
    initialized = true;

    printk_add(&sink);
    printk("debugcon: added printk sink\n");
}

CMDLINE_OPT("debugcon", init_debugcon);
