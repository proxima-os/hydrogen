#include "hydrogen/filesystem.h"
#include "arch/syscall.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/filesystem.h"
#include "kernel/syscall.h"
#include "vdso.h"

EXPORT int hydrogen_fs_chdir(int process, int rel, const void *path, size_t length) {
    return SYSCALL4(SYSCALL_FS_CHDIR, process, rel, path, length).error;
}

EXPORT int hydrogen_fs_chroot(int process, int rel, const void *path, size_t length) {
    return SYSCALL4(SYSCALL_FS_CHROOT, process, rel, path, length).error;
}

EXPORT hydrogen_ret_t hydrogen_fs_umask(int process, uint32_t mask) {
    return SYSCALL2(SYSCALL_FS_UMASK, process, mask);
}

EXPORT int hydrogen_fs_create(int rel, const void *path, size_t length, hydrogen_file_type_t type, uint32_t mode) {
    return SYSCALL5(SYSCALL_FS_CREATE, rel, path, length, type, mode).error;
}

EXPORT int hydrogen_fs_symlink(int rel, const void *path, size_t length, const void *target, size_t tlength) {
    return SYSCALL5(SYSCALL_FS_SYMLINK, rel, path, length, target, tlength).error;
}

EXPORT int hydrogen_fs_link(
        int rel,
        const void *path,
        size_t length,
        int trel,
        const void *target,
        size_t tlength,
        int flags
) {
    link_syscall_args_t args = {rel, trel, path, length, target, tlength, flags};
    return SYSCALL1(SYSCALL_FS_LINK, &args).error;
}

EXPORT int hydrogen_fs_unlink(int rel, const void *path, size_t length, int flags) {
    return SYSCALL4(SYSCALL_FS_UNLINK, rel, path, length, flags).error;
}

EXPORT int hydrogen_fs_rename(int rel, const void *path, size_t length, int trel, const void *target, size_t tlen) {
    return SYSCALL6(SYSCALL_FS_RENAME, rel, path, length, trel, target, tlen).error;
}

EXPORT int hydrogen_fs_access(int rel, const void *path, size_t length, uint32_t type, int flags) {
    return SYSCALL5(SYSCALL_FS_ACCESS, rel, path, length, type, flags).error;
}

EXPORT int hydrogen_fs_stat(int rel, const void *path, size_t length, hydrogen_file_information_t *info, int flags) {
    return SYSCALL4(SYSCALL_FS_STAT, rel, path, length, info).error;
}

EXPORT hydrogen_ret_t hydrogen_fs_readlink(int rel, const void *path, size_t length, void *buffer, size_t size) {
    return SYSCALL5(SYSCALL_FS_READLINK, rel, path, length, buffer, size);
}

EXPORT int hydrogen_fs_chmod(int rel, const void *path, size_t length, uint32_t mode, int flags) {
    return SYSCALL5(SYSCALL_FS_CHMOD, rel, path, length, mode, flags).error;
}

EXPORT int hydrogen_fs_chown(int rel, const void *path, size_t length, uint32_t uid, uint32_t gid, int flags) {
    return SYSCALL6(SYSCALL_FS_CHOWN, rel, path, length, uid, gid, flags).error;
}

EXPORT int hydrogen_fs_utime(
        int rel,
        const void *path,
        size_t length,
        __int128_t atime,
        __int128_t ctime,
        __int128_t mtime,
        int flags
) {
    utime_syscall_args_t args = {atime, ctime, mtime};
    return SYSCALL5(SYSCALL_FS_UTIME, rel, path, length, &args, flags).error;
}

EXPORT int hydrogen_fs_truncate(int rel, const void *path, size_t length, uint64_t size) {
    return SYSCALL4(SYSCALL_FS_TRUNCATE, rel, path, length, size).error;
}

EXPORT hydrogen_ret_t hydrogen_fs_open(int rel, const void *path, size_t length, int flags, uint32_t mode) {
    return SYSCALL5(SYSCALL_FS_OPEN, rel, path, length, flags, mode);
}

EXPORT hydrogen_ret_t
hydrogen_fs_mmap(int file, int vmm, uintptr_t hint, size_t size, uint32_t flags, uint64_t offset) {
    return SYSCALL6(SYSCALL_FS_MMAP, file, vmm, hint, size, flags, offset);
}

EXPORT hydrogen_ret_t hydrogen_fs_pread(int file, void *buffer, size_t size, uint64_t position) {
    return SYSCALL4(SYSCALL_FS_PREAD, file, buffer, size, position);
}

EXPORT hydrogen_ret_t hydrogen_fs_pwrite(int file, const void *buffer, size_t size, uint64_t position) {
    return SYSCALL4(SYSCALL_FS_PWRITE, file, buffer, size, position);
}

EXPORT hydrogen_ret_t hydrogen_fs_seek(int file, hydrogen_seek_anchor_t anchor, int64_t offset) {
    return SYSCALL3(SYSCALL_FS_SEEK, file, anchor, offset);
}

EXPORT hydrogen_ret_t hydrogen_fs_readdir(int file, void *buffer, size_t size) {
    return SYSCALL3(SYSCALL_FS_READDIR, file, buffer, size);
}

EXPORT hydrogen_ret_t hydrogen_fs_read(int file, void *buffer, size_t size) {
    return SYSCALL3(SYSCALL_FS_READ, file, buffer, size);
}

EXPORT hydrogen_ret_t hydrogen_fs_write(int file, const void *buffer, size_t size) {
    return SYSCALL3(SYSCALL_FS_WRITE, file, buffer, size);
}

EXPORT hydrogen_ret_t hydrogen_fs_fflags(int file, int flags) {
    return SYSCALL2(SYSCALL_FS_FFLAGS, file, flags);
}

EXPORT hydrogen_ret_t hydrogen_fs_fpath(int file, void *buffer, size_t size) {
    return SYSCALL3(SYSCALL_FS_FPATH, file, buffer, size);
}

EXPORT int hydrogen_fs_fstat(int file, hydrogen_file_information_t *info) {
    return SYSCALL2(SYSCALL_FS_FSTAT, file, info).error;
}

EXPORT int hydrogen_fs_fchmod(int file, uint32_t mode) {
    return SYSCALL2(SYSCALL_FS_FCHMOD, file, mode).error;
}

EXPORT int hydrogen_fs_fchown(int file, uint32_t uid, uint32_t gid) {
    return SYSCALL3(SYSCALL_FS_FCHOWN, file, uid, gid).error;
}

EXPORT int hydrogen_fs_futime(int file, __int128_t atime, __int128_t ctime, __int128_t mtime) {
    utime_syscall_args_t args = {atime, ctime, mtime};
    return SYSCALL2(SYSCALL_FS_FUTIME, file, &args).error;
}

EXPORT int hydrogen_fs_ftruncate(int file, uint64_t size) {
    return SYSCALL2(SYSCALL_FS_FTRUNCATE, file, size).error;
}

EXPORT hydrogen_ret_t hydrogen_fs_fopen(int file, int flags) {
    return SYSCALL2(SYSCALL_FS_FOPEN, file, flags);
}

EXPORT int hydrogen_fs_pipe(int fds[2], int flags) {
    hydrogen_ret_t ret = SYSCALL1(SYSCALL_FS_PIPE, flags);
    if (unlikely(ret.error)) return ret.error;

    fds[0] = ret.integer & 0xffffffff;
    fds[1] = ret.integer >> 32;

    return 0;
}

EXPORT hydrogen_ret_t hydrogen_fs_ioctl(int file, int request, void *buffer, size_t size) {
    return SYSCALL4(SYSCALL_FS_IOCTL, file, request, buffer, size);
}
