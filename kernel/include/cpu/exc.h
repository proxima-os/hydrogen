#pragma once

#include "cpu/idt.h"
#include "hydrogen/error.h"

_Noreturn void handle_fatal_exception(idt_frame_t *frame, void *);

void handle_user_exception(hydrogen_error_t error, const char *desc, idt_frame_t *frame, uintptr_t info[2]);

void init_exceptions(void);
