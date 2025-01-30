#pragma once

#include "kernel/pgsize.h"

#define KERNEL_STACK_PAGES 1
#define KERNEL_STACK_SIZE (KERNEL_STACK_PAGES << PAGE_SHIFT)
