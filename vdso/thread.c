#include "hydrogen/thread.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"
#include <cpuid.h>
#include <stdbool.h>
#include <stdint.h>

EXPORT hydrogen_ret_t hydrogen_thread_create(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) {
    hydrogen_handle_t ret;
    int error;
    SYSCALL4(SYSCALL_THREAD_CREATE, namespace, vm, pc, sp);
    return (hydrogen_ret_t){.error = error, .handle = ret};
}

EXPORT int hydrogen_thread_reinit(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) {
    UNUSED int ret;
    int error;
    SYSCALL4(SYSCALL_THREAD_REINIT, namespace, vm, pc, sp);
    return error;
}

EXPORT void hydrogen_thread_yield(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_THREAD_YIELD);
}

__attribute__((__noreturn__)) EXPORT void hydrogen_thread_exit(void) {
    UNUSED int ret, error;
    SYSCALL0(SYSCALL_THREAD_EXIT);
    __builtin_trap();
}

__attribute__((target("fsgsbase"))) static uintptr_t get_fs_base_fsgsbase(void) {
    return __builtin_ia32_rdfsbase64();
}

__attribute__((target("fsgsbase"))) static uintptr_t get_gs_base_fsgsbase(void) {
    return __builtin_ia32_rdgsbase64();
}

__attribute__((target("fsgsbase"))) static int set_fs_base_fsgsbase(uintptr_t base) {
    __builtin_ia32_wrfsbase64(base);
    return 0;
}

__attribute__((target("fsgsbase"))) static int set_gs_base_fsgsbase(uintptr_t base) {
    __builtin_ia32_wrgsbase64(base);
    return 0;
}

static uintptr_t get_fs_base_syscall(void) {
    uintptr_t ret;
    UNUSED int error;
    SYSCALL0(SYSCALL_X86_64_GET_FS_BASE);
    return ret;
}

static uintptr_t get_gs_base_syscall(void) {
    uintptr_t ret;
    UNUSED int error;
    SYSCALL0(SYSCALL_X86_64_GET_GS_BASE);
    return ret;
}

static int set_fs_base_syscall(uintptr_t base) {
    UNUSED int ret;
    int error;
    SYSCALL1(SYSCALL_X86_64_SET_FS_BASE, base);
    return error;
}

static int set_gs_base_syscall(uintptr_t base) {
    UNUSED int ret;
    int error;
    SYSCALL1(SYSCALL_X86_64_SET_GS_BASE, base);
    return error;
}

static bool have_fsgsbase(void) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return false;
    return ebx & 1;
}

static uintptr_t (*resolve_get_fs_base(void))(void) {
    return have_fsgsbase() ? get_fs_base_fsgsbase : get_fs_base_syscall;
}

static uintptr_t (*resolve_get_gs_base(void))(void) {
    return have_fsgsbase() ? get_gs_base_fsgsbase : get_gs_base_syscall;
}

static int (*resolve_set_fs_base(void))(uintptr_t) {
    return have_fsgsbase() ? set_fs_base_fsgsbase : set_fs_base_syscall;
}

static int (*resolve_set_gs_base(void))(uintptr_t) {
    return have_fsgsbase() ? set_gs_base_fsgsbase : set_gs_base_syscall;
}

__attribute__((ifunc("resolve_get_fs_base"))) EXPORT uintptr_t hydrogen_x86_64_get_fs_base();
__attribute__((ifunc("resolve_get_gs_base"))) EXPORT uintptr_t hydrogen_x86_64_get_gs_base();
__attribute__((ifunc("resolve_set_fs_base"))) EXPORT int hydrogen_x86_64_set_fs_base(uintptr_t address);
__attribute__((ifunc("resolve_set_gs_base"))) EXPORT int hydrogen_x86_64_set_gs_base(uintptr_t address);
