#pragma once

#include "util/object.h"
#include <stdbool.h>

extern object_t io_object;

bool is_io_object(object_t *obj);
