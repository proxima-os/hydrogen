#pragma once

#include "cpu/idt.h"

_Noreturn void handle_fatal_exception(idt_frame_t *frame, void *);

void init_exceptions(void);
