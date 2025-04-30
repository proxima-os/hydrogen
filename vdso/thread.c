#include "hydrogen/thread.h"
#include "hydrogen/handle.h"
#include "hydrogen/types.h"
#include "kernel/syscall.h"
#include "syscall.h"
#include "vdso.h"
#include <cpuid.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

EXPORT hydrogen_ret_t hydrogen_thread_create(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) {
    return SYSCALL4(SYSCALL_THREAD_CREATE, namespace, vm, pc, sp);
}

EXPORT int hydrogen_thread_reinit(hydrogen_handle_t namespace, hydrogen_handle_t vm, void *pc, void *sp) {
    return SYSCALL4(SYSCALL_THREAD_REINIT, namespace, vm, pc, sp).error;
}

EXPORT hydrogen_ret_t hydrogen_thread_clone(hydrogen_handle_t namespace, hydrogen_handle_t vm) {
    return SYSCALL2(SYSCALL_THREAD_CLONE, namespace, vm);
}

EXPORT hydrogen_ret_t hydrogen_thread_fork(hydrogen_handle_t namespace) {
    hydrogen_ret_t ret;
    hydrogen_handle_t p0 = NULL;
    hydrogen_handle_t orig_ns = namespace;

    // This has to be done in one asm block, because there must be no writes to memory between
    // the call to `hydrogen_vm_clone` and `hydrogen_thread_clone`.
    asm("syscall \n\t"             // Clone the vm
        "test %%eax, %%eax \n\t"   // Check if the vm clone was successful
        "jnz 1f \n\t"              // If not, skip straight to return
        "mov %[tcvec], %%eax \n\t" // Set syscall number for thread clone
        "mov %%rsi, %%rdi \n\t"    // Use namespace handle as first parameter
        "mov %%rdx, %%rsi \n\t"    // Use cloned address space as second parameter
        "syscall \n\t"             // Clone the thread
        "1: "
        : "=A"(ret), "+D"(p0), "+S"(namespace)
        : "a"(SYSCALL_VM_CLONE), [tcvec] "i"(SYSCALL_THREAD_CLONE)
        : "rcx", "r11", "memory");

    if (orig_ns != namespace) {
        // `namespace` is now the created VM.
        // Close the handle to it in the creator.

        if (ret.error != 0 || ret.handle != NULL) {
            ASSERT_OK_INT(hydrogen_handle_close(NULL, namespace));
        }
    }

    return ret;
}

EXPORT void hydrogen_thread_yield(void) {
    ASSERT_OK(SYSCALL0(SYSCALL_THREAD_YIELD));
}

__attribute__((__noreturn__)) EXPORT void hydrogen_thread_exit(void) {
    ASSERT_OK(SYSCALL0(SYSCALL_THREAD_EXIT));
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
    return ASSERT_OK(SYSCALL0(SYSCALL_X86_64_GET_FS_BASE)).integer;
}

static uintptr_t get_gs_base_syscall(void) {
    return ASSERT_OK(SYSCALL0(SYSCALL_X86_64_GET_GS_BASE)).integer;
}

static int set_fs_base_syscall(uintptr_t base) {
    return SYSCALL1(SYSCALL_X86_64_SET_FS_BASE, base).error;
}

static int set_gs_base_syscall(uintptr_t base) {
    return SYSCALL1(SYSCALL_X86_64_SET_GS_BASE, base).error;
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
