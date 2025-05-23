#ifndef HYDROGEN_FILESYSTEM_H
#define HYDROGEN_FILESYSTEM_H

#include "hydrogen/types.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HYDROGEN_FILE_TIME_NOW ((__int128_t)(((__uint128_t)INT64_MAX << 64) | UINT64_MAX))
#define HYDROGEN_FILE_TIME_OMIT (-HYDROGEN_FILE_TIME_NOW - 1)

#define HYDROGEN_FILE_READ (1u << 0)
#define HYDROGEN_FILE_WRITE (1u << 1)
#define HYDROGEN_FILE_EXEC (1u << 2)

typedef enum {
    HYDROGEN_UNKNOWN_FILE_TYPE,
    HYDROGEN_REGULAR_FILE,
    HYDROGEN_DIRECTORY,
    HYDROGEN_SYMLINK,
    HYDROGEN_CHARACTER_DEVICE,
    HYDROGEN_BLOCK_DEVICE,
    HYDROGEN_FIFO,
} hydrogen_file_type_t;

typedef struct {
    uint64_t filesystem_id;
    uint64_t id;
    uint64_t links;
    uint64_t blocks;
    uint64_t size;
    size_t block_size;
    __int128_t atime;
    __int128_t btime;
    __int128_t ctime;
    __int128_t mtime;
    hydrogen_file_type_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
} hydrogen_file_information_t;

typedef enum {
    HYDROGEN_SEEK_BEGIN,
    HYDROGEN_SEEK_CURRENT,
    HYDROGEN_SEEK_END,
} hydrogen_seek_anchor_t;

typedef struct {
    size_t size;
    uint64_t id;
    size_t name_length;
    hydrogen_file_type_t type;
    unsigned char name[0];
} hydrogen_directory_entry_t;

int hydrogen_fs_chdir(int process, int rel, const void *path, size_t length) __asm__("__hydrogen_fs_chdir");
int hydrogen_fs_chroot(int process, int rel, const void *path, size_t length) __asm__("__hydrogen_fs_chroot");
hydrogen_ret_t hydrogen_fs_umask(int process, uint32_t mask) __asm__("__hydrogen_fs_umask");

int hydrogen_fs_create(int rel, const void *path, size_t length, hydrogen_file_type_t type, uint32_t mode) __asm__(
        "__hydrogen_fs_create"
);
int hydrogen_fs_symlink(int rel, const void *path, size_t length, const void *target, size_t tlength) __asm__(
        "__hydrogen_fs_symlink"
);
int hydrogen_fs_link(
        int rel,
        const void *path,
        size_t length,
        int trel,
        const void *target,
        size_t tlength,
        int flags
) __asm__("__hydrogen_fs_link");
int hydrogen_fs_unlink(int rel, const void *path, size_t length, int flags) __asm__("__hydrogen_fs_unlink");
int hydrogen_fs_rename(int rel, const void *path, size_t length, int trel, const void *target, size_t tlen) __asm__(
        "__hydrogen_fs_rename"
);

int hydrogen_fs_access(int rel, const void *path, size_t length, uint32_t type, int flags) __asm__(
        "__hydrogen_fs_access"
);
int hydrogen_fs_stat(int rel, const void *path, size_t length, hydrogen_file_information_t *info, int flags) __asm__(
        "__hydrogen_fs_stat"
);
int hydrogen_fs_fstat(int file, hydrogen_file_information_t *info) __asm__("__hydrogen_fs_fstat");
hydrogen_ret_t hydrogen_fs_readlink(int rel, const void *path, size_t length, void *buffer, size_t size) __asm__(
        "__hydrogen_fs_readlink"
);
int hydrogen_fs_chmod(int rel, const void *path, size_t length, uint32_t mode, int flags) __asm__(
        "__hydrogen_fs_chmod"
);
int hydrogen_fs_fchmod(int file, uint32_t mode) __asm__("__hydrogen_fs_fchmod");
int hydrogen_fs_chown(int rel, const void *path, size_t length, uint32_t uid, uint32_t gid, int flags) __asm__(
        "__hydrogen_fs_chown"
);
int hydrogen_fs_fchown(int file, uint32_t uid, uint32_t gid) __asm__("__hydrogen_fs_fchown");
int hydrogen_fs_utime(
        int rel,
        const void *path,
        size_t length,
        __int128_t atime,
        __int128_t ctime,
        __int128_t mtime,
        int flags
) __asm__("__hydrogen_fs_utime");
int hydrogen_fs_futime(int file, __int128_t atime, __int128_t ctime, __int128_t mtime) __asm__("__hydrogen_fs_futime");
int hydrogen_fs_truncate(int rel, const void *path, size_t length, uint64_t size) __asm__("__hydrogen_fs_truncate");
int hydrogen_fs_ftruncate(int file, uint64_t size) __asm__("__hydrogen_fs_ftruncate");

hydrogen_ret_t hydrogen_fs_open(int rel, const void *path, size_t length, int flags, uint32_t mode) __asm__(
        "__hydrogen_fs_open"
);
hydrogen_ret_t hydrogen_fs_fopen(int file, int flags) __asm__("__hydrogen_fs_fopen");
int hydrogen_fs_pipe(int fds[2], int flags) __asm__("__hydrogen_fs_pipe");
hydrogen_ret_t hydrogen_fs_mmap(
        int file,
        int vmm,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        uint64_t offset
) __asm__("__hydrogen_fs_mmap");
hydrogen_ret_t hydrogen_fs_pread(int file, void *buffer, size_t size, uint64_t position) __asm__("__hydrogen_fs_pread");
hydrogen_ret_t hydrogen_fs_pwrite(int file, const void *buffer, size_t size, uint64_t position) __asm__(
        "__hydrogen_fs_pwrite"
);
hydrogen_ret_t hydrogen_fs_seek(int file, hydrogen_seek_anchor_t anchor, int64_t offset) __asm__("__hydrogen_fs_seek");
hydrogen_ret_t hydrogen_fs_readdir(int file, void *buffer, size_t size) __asm__("__hydrogen_fs_readdir");
hydrogen_ret_t hydrogen_fs_read(int file, void *buffer, size_t size) __asm__("__hydrogen_fs_read");
hydrogen_ret_t hydrogen_fs_write(int file, const void *buffer, size_t size) __asm__("__hydrogen_fs_write");
hydrogen_ret_t hydrogen_fs_ioctl(int file, int request, void *buffer, size_t size) __asm__("__hydrogen_fs_ioctl");

hydrogen_ret_t hydrogen_fs_fflags(int file, int flags) __asm__("__hydrogen_fs_fflags");
hydrogen_ret_t hydrogen_fs_fpath(int file, void *buffer, size_t size) __asm__("__hydrogen_fs_fpath");

#ifdef __cplusplus
};
#endif

#endif /* HYDROGEN_FILESYSTEM_H */
