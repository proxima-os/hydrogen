#include "sys/syscall.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "cpu/xsave.h"
#include "hydrogen/error.h"
#include "hydrogen/handle.h"
#include "hydrogen/io.h"
#include "hydrogen/log.h"
#include "hydrogen/memory.h"
#include "hydrogen/thread.h"
#include "hydrogen/time.h"
#include "kernel/syscall.h"
#include "mem/pmap.h"
#include "sys/vdso.h"
#include <stdint.h>

_Static_assert(SEL_KCODE + 8 == SEL_KDATA, "Selector layout incompatible with syscall instruction");
_Static_assert(SEL_UDATA + 8 == SEL_UCODE, "Selector layout incompatible with syscall instruction");

extern const void syscall_entry;

void init_syscall(void) {
}

void init_syscall_cpu(void) {
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | MSR_EFER_SCE);
    wrmsr(MSR_STAR, ((uint64_t)(SEL_UDATA - 8) << 48) | ((uint64_t)SEL_KCODE << 32));
    wrmsr(MSR_LSTAR, (uintptr_t)&syscall_entry);
    wrmsr(MSR_FMASK, 0x40600); // Clear AC, IF, and DF on syscall entry
}

static hydrogen_error_t do_syscall(size_t *ret, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    syscall_vec_t vec = *ret;
    hydrogen_error_t err;
    hydrogen_handle_t h;

    switch (vec) {
    case SYSCALL_THREAD_EXIT: hydrogen_thread_exit();
    case SYSCALL_LOG_WRITE: return hydrogen_log_write((hydrogen_handle_t)a0, (const void *)a1, a2);
    case SYSCALL_GET_TIME: *ret = hydrogen_get_time(); return HYDROGEN_SUCCESS;
    case SYSCALL_NAMESPACE_CREATE:
        err = hydrogen_namespace_create(&h);
        *ret = (size_t)h;
        return err;
    case SYSCALL_HANDLE_CREATE:
        err = hydrogen_handle_create((hydrogen_handle_t)a0, (hydrogen_handle_t)a1, a2, &h);
        *ret = (size_t)h;
        return err;
    case SYSCALL_HANDLE_CLOSE: return hydrogen_handle_close((hydrogen_handle_t)a0, (hydrogen_handle_t)a1);
    case SYSCALL_VM_CREATE:
        err = hydrogen_vm_create(&h);
        *ret = (size_t)h;
        return err;
    case SYSCALL_VM_CLONE:
        err = hydrogen_vm_clone(&h, (hydrogen_handle_t)a0);
        *ret = (size_t)h;
        return err;
    case SYSCALL_VM_MAP:
        err = hydrogen_vm_map((hydrogen_handle_t)a0, &a1, a2, a3, (hydrogen_handle_t)a4, a5);
        *ret = a1;
        return err;
    case SYSCALL_VM_MAP_VDSO:
        err = hydrogen_vm_map_vdso((hydrogen_handle_t)a0, &a1);
        *ret = a1;
        return err;
    case SYSCALL_VM_REMAP: return hydrogen_vm_remap((hydrogen_handle_t)a0, a1, a2, a3);
    case SYSCALL_VM_UNMAP: return hydrogen_vm_unmap((hydrogen_handle_t)a0, a1, a2);
    case SYSCALL_IO_ENABLE: return hydrogen_io_enable((hydrogen_handle_t)a0);
    case SYSCALL_IO_DISABLE: hydrogen_io_disable(); return HYDROGEN_SUCCESS;
    default: return HYDROGEN_INVALID_SYSCALL;
    }
}

__attribute__((used)) void syscall_dispatch(idt_frame_t *frame) {
    frame->cs = SEL_UCODE;
    frame->ss = SEL_UDATA;
    current_thread->user_regs = frame;
    enable_irq();

    if (!is_in_vdso(frame->rip)) {
        uintptr_t info[2] = {};
        handle_user_exception(HYDROGEN_INVALID_ARGUMENT, "system call from outside vdso", frame, info);
        return;
    }

    frame->rdx = do_syscall(&frame->rax, frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
}

_Noreturn void do_enter_umode(uintptr_t rip, uintptr_t rsp, uintptr_t rflags, uintptr_t cs, uintptr_t ss);

_Noreturn void enter_user_mode(uintptr_t rip, uintptr_t rsp) {
    xreset();
    do_enter_umode(rip, rsp, 0x200, SEL_UCODE, SEL_UDATA);
}

hydrogen_error_t verify_user_pointer(const void *ptr, size_t size) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t end = addr + size;
    if (end < addr) return HYDROGEN_INVALID_POINTER;
    if (end > max_user_address) return HYDROGEN_INVALID_POINTER;
    return HYDROGEN_SUCCESS;
}
