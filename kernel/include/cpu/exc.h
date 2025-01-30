#pragma once

#include "cpu/idt.h"

void init_exc(void);

void handle_fatal_exception(idt_frame_t *frame);
