#ifndef HYDROGEN_VFS_H
#define HYDROGEN_VFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t fs;
    uint64_t id;
    uint64_t links;
    uint64_t size;
    uint64_t blocks;
    uint64_t block_size;
    int64_t atime;
    int64_t btime;
    int64_t ctime;
    int64_t mtime;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
} hydrogen_stat_t;

typedef enum {
    HYDROGEN_WHENCE_SET,
    HYDROGEN_WHENCE_CUR,
    HYDROGEN_WHENCE_END,
} hydrogen_whence_t;

typedef struct {
    size_t transferred;
    int error;
} hydrogen_io_res_t;

int hydrogen_open(int base, const void *path, size_t path_len, int flags, uint32_t mode);
int hydrogen_reopen(int fd, int flags);
int hydrogen_close(int fd);

int hydrogen_unlink(int base, const void *path, size_t path_len, bool dir);
int hydrogen_rename(
        int src_base,
        const void *src_path,
        size_t src_path_len,
        int dst_base,
        const void *dst_path,
        size_t dst_path_len
);

int hydrogen_stat(int base, const void *path, size_t path_len, hydrogen_stat_t *out, bool follow);

int hydrogen_seek(int fd, uint64_t *offset, hydrogen_whence_t whence);
hydrogen_io_res_t hydrogen_read(int fd, void *buffer, size_t size);
hydrogen_io_res_t hydrogen_write(int fd, const void *buffer, size_t size);
hydrogen_io_res_t hydrogen_pread(int fd, void *buffer, size_t size, uint64_t position);
hydrogen_io_res_t hydrogen_pwrite(int fd, const void *buffer, size_t size, uint64_t position);

#ifdef __cplusplus
};
#endif

#endif // HYDROGEN_VFS_H
