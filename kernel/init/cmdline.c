#include "init/cmdline.h"
#include "limine.h"
#include "sections.h"
#include <stddef.h>
#include <string.h>

extern const cmdline_opt_t __cmdline_start[];
extern const cmdline_opt_t __cmdline_end[];

static const cmdline_opt_t *find_option(const char *name) {
    // the linker script sorts this array by name, so we can do a binary search

    const cmdline_opt_t *start = __cmdline_start;
    const cmdline_opt_t *end = __cmdline_end;

    while (start != end) {
        const cmdline_opt_t *candidate = start + ((end - start) / 2);
        int cmp = strcmp(name, candidate->name);

        if (cmp == 0) {
            return candidate;
        } else if (cmp < 0) {
            end = candidate;
        } else {
            start = candidate + 1;
        }
    }

    return NULL;
}

void parse_command_line(void) {
    static LIMINE_REQ struct limine_executable_cmdline_request cmdline_req = {.id = LIMINE_EXECUTABLE_CMDLINE_REQUEST};
    if (!cmdline_req.response) return;
    char *text = cmdline_req.response->cmdline;

    for (;;) {
        char c;
        while ((c = *text) == ' ') text++;
        if (!c) break;

        char *end = strchr(text, ' ');
        if (end) *end = 0;

        char *value_start = strchr(text, '=');
        if (value_start) *value_start = 0;

        const cmdline_opt_t *option = find_option(text);

        if (option) {
            option->func(text, value_start ? value_start + 1 : NULL);
        }

        if (!end) break;
        text = end + 1;
    }
}
