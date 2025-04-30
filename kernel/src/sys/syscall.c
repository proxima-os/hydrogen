#include "sys/syscall.h"
#include "asm/irq.h"
#include "asm/msr.h"
#include "cpu/cpu.h"
#include "cpu/exc.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "cpu/xsave.h"
#include "errno.h"
#include "hydrogen/handle.h"
#include "hydrogen/io.h"
#include "hydrogen/log.h"
#include "hydrogen/memory.h"
#include "hydrogen/thread.h"
#include "hydrogen/time.h"
#include "hydrogen/types.h"
#include "kernel/return.h"
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

static hydrogen_ret_t do_syscall(syscall_vec_t vec, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    switch (vec) {
    case SYSCALL_THREAD_EXIT: hydrogen_thread_exit(); return RET_ERROR(0);
    case SYSCALL_LOG_WRITE: return RET_ERROR(hydrogen_log_write((hydrogen_handle_t)a0, (const void *)a1, a2));
    case SYSCALL_GET_TIME: return RET_INTEGER(hydrogen_get_time());
    case SYSCALL_NAMESPACE_CREATE: return hydrogen_namespace_create();
    case SYSCALL_HANDLE_CREATE:
        return hydrogen_handle_create((hydrogen_handle_t)a0, (hydrogen_handle_t)a1, (hydrogen_handle_t)a2, a3);
    case SYSCALL_HANDLE_CLOSE: return RET_ERROR(hydrogen_handle_close((hydrogen_handle_t)a0, (hydrogen_handle_t)a1));
    case SYSCALL_VM_CREATE: return hydrogen_vm_create();
    case SYSCALL_VM_CLONE: return hydrogen_vm_clone((hydrogen_handle_t)a0);
    case SYSCALL_VM_MAP: return hydrogen_vm_map((hydrogen_handle_t)a0, a1, a2, a3, (hydrogen_handle_t)a4, a5);
    case SYSCALL_VM_MAP_VDSO: return hydrogen_vm_map_vdso((hydrogen_handle_t)a0);
    case SYSCALL_VM_MOVE: return hydrogen_vm_move((hydrogen_handle_t)a0, a1, a2, (hydrogen_handle_t)a3, a4, a5);
    case SYSCALL_VM_REMAP: return RET_ERROR(hydrogen_vm_remap((hydrogen_handle_t)a0, a1, a2, a3));
    case SYSCALL_VM_UNMAP: return RET_ERROR(hydrogen_vm_unmap((hydrogen_handle_t)a0, a1, a2));
    case SYSCALL_VM_WRITE: return RET_ERROR(hydrogen_vm_write((hydrogen_handle_t)a0, a1, (const void *)a2, a3));
    case SYSCALL_VM_FILL: return RET_ERROR(hydrogen_vm_fill((hydrogen_handle_t)a0, a1, a2, a3));
    case SYSCALL_VM_READ: return RET_ERROR(hydrogen_vm_read((hydrogen_handle_t)a0, (void *)a1, a2, a3));
    case SYSCALL_IO_ENABLE: return RET_ERROR(hydrogen_io_enable((hydrogen_handle_t)a0));
    case SYSCALL_IO_DISABLE: hydrogen_io_disable(); return RET_ERROR(0);
    case SYSCALL_X86_64_GET_FS_BASE: return RET_INTEGER(hydrogen_x86_64_get_fs_base());
    case SYSCALL_X86_64_GET_GS_BASE: return RET_INTEGER(hydrogen_x86_64_get_gs_base());
    case SYSCALL_X86_64_SET_FS_BASE: return RET_ERROR(hydrogen_x86_64_set_fs_base(a0));
    case SYSCALL_X86_64_SET_GS_BASE: return RET_ERROR(hydrogen_x86_64_set_gs_base(a0));
    case SYSCALL_THREAD_CREATE:
        return hydrogen_thread_create((hydrogen_handle_t)a0, (hydrogen_handle_t)a1, (void *)a2, (void *)a3);
    case SYSCALL_THREAD_REINIT:
        return RET_ERROR(hydrogen_thread_reinit((hydrogen_handle_t)a0, (hydrogen_handle_t)a1, (void *)a2, (void *)a3));
    case SYSCALL_THREAD_YIELD: hydrogen_thread_yield(); return RET_ERROR(0);
    case SYSCALL_SLEEP: return RET_ERROR(hydrogen_sleep(a0));
    case SYSCALL_NAMESPACE_CLONE: return hydrogen_namespace_clone((hydrogen_handle_t)a0);
    default: return RET_ERROR(ENOSYS);
    }
}

__attribute__((used)) void syscall_dispatch(idt_frame_t *frame) {
    frame->cs = SEL_UCODE;
    frame->ss = SEL_UDATA;
    current_thread->user_regs = frame;
    enable_irq();

    if (!is_in_vdso(frame->rip)) {
        uintptr_t info[2] = {};
        handle_user_exception(EINVAL, "system call from outside vdso", frame, info);
        return;
    }

    hydrogen_ret_t ret = do_syscall(frame->rax, frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8, frame->r9);
    frame->rax = ret.error;
    frame->rdx = ret.integer;
}

_Noreturn void do_enter_umode(uintptr_t rip, uintptr_t rsp, uintptr_t rflags, uintptr_t cs, uintptr_t ss);

_Noreturn void enter_user_mode(uintptr_t rip, uintptr_t rsp) {
    xreset();
    do_enter_umode(rip, rsp, 0x200, SEL_UCODE, SEL_UDATA);
}

int verify_user_pointer(const void *ptr, size_t size) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t end = addr + size;
    if (end < addr) return EFAULT;
    if (end > max_user_address) return EFAULT;
    return 0;
}
