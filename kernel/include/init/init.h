#pragma once

#include "hydrogen/types.h"
#include <stdint.h>

uintptr_t load_init_image(hydrogen_handle_t vm);
uintptr_t create_init_stack(uintptr_t vdso_addr);
