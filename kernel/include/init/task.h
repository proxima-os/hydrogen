#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct init_task {
    char *name;
    void (*func)(void);
    struct init_task **target;
    struct init_task **dependencies;
    size_t num_dependencies;
    void *run_id;
} init_task_t;

#define INIT_DECLARE(name) extern init_task_t __init_task_##name
#define INIT_REFERENCE(name) &__init_task_##name
#define INIT_DEFINE_TARGET(name, func, target, ...)               \
    static char __init_name_##name[] = #name;                     \
    static init_task_t *__init_deps_##name[] = {__VA_ARGS__};     \
    extern init_task_t *__inittask_start_##target[];              \
    init_task_t __init_task_##name = {                            \
        __init_name_##name,                                       \
        (func),                                                   \
        __inittask_start_##target,                                \
        __init_deps_##name,                                       \
        sizeof(__init_deps_##name) / sizeof(*__init_deps_##name), \
        (void *)(uintptr_t)-1                                     \
    };                                                            \
    __attribute__((used, section(".inittask." #target))) static init_task_t *__init_taskp_##name = &__init_task_##name

#define INIT_DEFINE_EARLY(name, func, ...) INIT_DEFINE_TARGET(name, func, early, ##__VA_ARGS__)
#define INIT_DEFINE_EARLY_AP(name, func, ...) INIT_DEFINE_TARGET(name, func, earlyap, ##__VA_ARGS__)
#define INIT_DEFINE(name, func, ...) INIT_DEFINE_TARGET(name, func, dflt, ##__VA_ARGS__)
#define INIT_DEFINE_AP(name, func, ...) INIT_DEFINE_TARGET(name, func, dfltap, ##__VA_ARGS__)
