#include "hydrogen/vfs.h"
#include "compiler.h"
#include "sys/sysvecs.h"
#include "syscall.h"

int hydrogen_open(int base, const void *path, size_t path_len, int flags, uint32_t mode) {
    syscall_result_t result = syscall5(SYS_OPEN, base, (uintptr_t)path, path_len, flags, mode);
    if (unlikely(result.error)) return -result.error;
    return result.value.num;
}

int hydrogen_reopen(int fd, int flags) {
    syscall_result_t result = syscall2(SYS_REOPEN, fd, flags);
    if (unlikely(result.error)) return -result.error;
    return result.value.num;
}

int hydrogen_close(int fd) {
    return syscall1(SYS_CLOSE, fd).error;
}

int hydrogen_unlink(int base, const void *path, size_t path_len, bool dir) {
    return syscall4(SYS_UNLINK, base, (uintptr_t)path, path_len, dir).error;
}

int hydrogen_rename(
        int src_base,
        const void *src_path,
        size_t src_path_len,
        int dst_base,
        const void *dst_path,
        size_t dst_path_len
) {
    return syscall6(
            SYS_RENAME,
            src_base,
            (uintptr_t)src_path,
            src_path_len,
            dst_base,
            (uintptr_t)dst_path,
            dst_path_len
    ).error;
}

int hydrogen_stat(int base, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow) {
    return syscall5(SYS_STAT, base, (uintptr_t)path, path_len, (uintptr_t)out, follow).error;
}

int hydrogen_seek(int fd, uint64_t *offset, hydrogen_whence_t whence) {
    syscall_result_t result = syscall3(SYS_SEEK, fd, *offset, whence);
    if (unlikely(result.error)) return result.error;

    *offset = result.value.num;
    return 0;
}

hydrogen_io_res_t hydrogen_read(int fd, void *buffer, size_t size) {
    syscall_result_t result = syscall3(SYS_READ, fd, (uintptr_t)buffer, size);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_write(int fd, const void *buffer, size_t size) {
    syscall_result_t result = syscall3(SYS_WRITE, fd, (uintptr_t)buffer, size);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_pread(int fd, void *buffer, size_t size, uint64_t position) {
    syscall_result_t result = syscall4(SYS_PREAD, fd, (uintptr_t)buffer, size, position);
    return (hydrogen_io_res_t){result.value.num, result.error};
}

hydrogen_io_res_t hydrogen_pwrite(int fd, const void *buffer, size_t size, uint64_t position) {
    syscall_result_t result = syscall4(SYS_PWRITE, fd, (uintptr_t)buffer, size, position);
    return (hydrogen_io_res_t){result.value.num, result.error};
}
