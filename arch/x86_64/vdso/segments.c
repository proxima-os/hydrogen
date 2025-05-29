#include "arch/syscall.h"
#include "kernel/vdso.h"
#include "kernel/x86_64/syscall.h"
#include "vdso.h"
#include <hydrogen/x86_64/segments.h>
#include <stdint.h>

static uintptr_t get_fs_base_syscall(void) {
    return SYSCALL0(X86_64_SYSCALL_GET_FS_BASE).integer;
}

static uintptr_t get_gs_base_syscall(void) {
    return SYSCALL0(X86_64_SYSCALL_GET_FS_BASE).integer;
}

static int set_fs_base_syscall(uintptr_t value) {
    return SYSCALL1(X86_64_SYSCALL_SET_FS_BASE, value).error;
}

static int set_gs_base_syscall(uintptr_t value) {
    return SYSCALL1(X86_64_SYSCALL_SET_FS_BASE, value).error;
}

__attribute__((target("fsgsbase"))) static uintptr_t get_fs_base_fsgsbase(void) {
    return __builtin_ia32_rdfsbase64();
}

__attribute__((target("fsgsbase"))) static uintptr_t get_gs_base_fsgsbase(void) {
    return __builtin_ia32_rdgsbase64();
}

__attribute__((target("fsgsbase"))) static int set_fs_base_fsgsbase(uintptr_t value) {
    __builtin_ia32_wrfsbase64(value);
    return 0;
}

__attribute__((target("fsgsbase"))) static int set_gs_base_fsgsbase(uintptr_t value) {
    __builtin_ia32_wrgsbase64(value);
    return 0;
}

static uintptr_t (*resolve_get_fs_base(void))(void) {
    return vdso_info.arch.fsgsbase ? get_fs_base_fsgsbase : get_fs_base_syscall;
}

static uintptr_t (*resolve_get_gs_base(void))(void) {
    return vdso_info.arch.fsgsbase ? get_gs_base_fsgsbase : get_gs_base_syscall;
}

static int (*resolve_set_fs_base(void))(uintptr_t) {
    return vdso_info.arch.fsgsbase ? set_fs_base_fsgsbase : set_fs_base_syscall;
}

static int (*resolve_set_gs_base(void))(uintptr_t) {
    return vdso_info.arch.fsgsbase ? set_gs_base_fsgsbase : set_gs_base_syscall;
}

__attribute__((ifunc("resolve_get_fs_base"))) EXPORT uintptr_t hydrogen_x86_64_get_fs_base(void);
__attribute__((ifunc("resolve_get_gs_base"))) EXPORT uintptr_t hydrogen_x86_64_get_gs_base(void);
__attribute__((ifunc("resolve_set_fs_base"))) EXPORT int hydrogen_x86_64_set_fs_base(uintptr_t value);
__attribute__((ifunc("resolve_set_gs_base"))) EXPORT int hydrogen_x86_64_set_gs_base(uintptr_t value);
