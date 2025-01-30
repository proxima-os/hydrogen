#include "asm/idle.h"
#include "compiler.h"
#include "limine.h"
#include "sections.h"

__attribute__((used, section(".requests0"))) static LIMINE_REQUESTS_START_MARKER;
__attribute__((used, section(".requests2"))) static LIMINE_REQUESTS_END_MARKER;

LIMINE_REQ LIMINE_BASE_REVISION(3);

USED _Noreturn void kernel_main(void) {
    for (;;) arch_cpu_idle();
}
