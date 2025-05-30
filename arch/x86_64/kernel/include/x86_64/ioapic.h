#pragma once

#include "drv/interrupt.h"
#include "init/task.h"

INIT_DECLARE(x86_64_ioapic);

extern irq_controller_t x86_64_gsi_controller;
extern irq_controller_t x86_64_isa_controller;
