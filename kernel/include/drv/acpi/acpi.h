#pragma once

#include "init/task.h"
#include "uacpi/namespace.h"
#include "uacpi/utilities.h"

typedef struct acpi_driver {
    const char *name;
    const char *const *pnp_ids;
    size_t num_pnp_ids;
    int (*init_device)(uacpi_namespace_node *node, uacpi_namespace_node_info *info);
} acpi_driver_t;

#define ACPI_DRIVER3(id, name, func, ...)                                                  \
    static const char *const __acpidrv_id_##id[] = {__VA_ARGS__};                          \
    __attribute__((used, section(".acpidrv"))) static const acpi_driver_t __acpidrv_##id = \
        {name, __acpidrv_id_##id, sizeof(__acpidrv_id_##id) / sizeof(*__acpidrv_id_##id), (func)}
#define ACPI_DRIVER2(id, name, func, ...) ACPI_DRIVER3(id, name, func, ##__VA_ARGS__)
#define ACPI_DRIVER(name, func, ...) ACPI_DRIVER2(__COUNTER__, name, func, ##__VA_ARGS__)

INIT_DECLARE(acpi_tables);
INIT_DECLARE(acpi);
