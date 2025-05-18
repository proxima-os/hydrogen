#pragma once

#include "init/task.h"
#include "proc/event.h"
#include "proc/sched.h"

INIT_DECLARE(mount_rootfs);
INIT_DECLARE(verify_loader_revision);

_Noreturn void smp_init_current(event_t *event);
void smp_init_current_late(void);

void schedule_kernel_task(task_t *task);
