#pragma once

#include "arch/usercopy.h"
#include "fs/fifo.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/object.h"
#include "util/refcount.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/stat.h>
#include <hydrogen/types.h>
#include <stddef.h>
#include <stdint.h>

#define S_IRWXO (__S_IROTH | __S_IWOTH | __S_IXOTH)
#define S_IRWXG (__S_IRGRP | __S_IWGRP | __S_IXGRP)
#define S_IRWXU (__S_IRUSR | __S_IWUSR | __S_IXUSR)
#define FILE_PERM_BITS (S_IRWXU | S_IRWXG | S_IRWXO)
#define FILE_MAKE_BITS (__S_ISVTX | FILE_PERM_BITS)
#define FILE_MODE_BITS (__S_ISUID | __S_ISGID | FILE_MAKE_BITS)

#define FILE_PERM_FLAGS (__O_WRONLY | __O_RDONLY)
#define FILE_DESC_FLAGS (__O_NONBLOCK | __O_APPEND | FILE_PERM_FLAGS)
#define FILE_OPEN_FLAGS                                                                                         \
    (__O_NOCTTY | __O_TMPFILE | __O_CLOEXEC | __O_TRUNC | __O_NOFOLLOW | __O_EXCL | __O_DIRECTORY | __O_CREAT | \
     __O_CLOFORK | FILE_DESC_FLAGS)

#define FILESYSTEM_READ_ONLY (1u << 0)
#define FILESYSTEM_NO_SETUID (1u << 1)

typedef struct dentry dentry_t;
typedef struct file file_t;
typedef struct filesystem filesystem_t;
typedef struct inode inode_t;

struct ident;
struct process;
struct vmm;

typedef struct {
    void *data;
    size_t size;
    uint64_t hash;
} dname_t;

struct dentry {
    refcnt_t references;

    filesystem_t *fs;
    dentry_t *parent;
    hlist_node_t node;
    hlist_t *children;
    size_t capacity;
    size_t count;
    size_t real_count; // the number of entries that have inodes

    list_t child_list;
    list_node_t list_node;

    dname_t name;

    mutex_t lock;
    inode_t *inode;
    filesystem_t *mounted;
    bool present;
};

typedef struct {
    object_ops_t base;
    hydrogen_ret_t (*seek)(file_t *self, hydrogen_seek_anchor_t anchor, int64_t offset);
    hydrogen_ret_t (*read)(file_t *self, void *buffer, size_t size, uint64_t position);
    hydrogen_ret_t (*readdir)(file_t *self, void *buffer, size_t size);
    hydrogen_ret_t (*write)(file_t *self, const void *buffer, size_t size, uint64_t position, bool rpos);
    hydrogen_ret_t (*mmap)(
        file_t *self,
        object_rights_t rights,
        struct vmm *vmm,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        uint64_t offset
    );
    hydrogen_ret_t (*ioctl)(file_t *self, unsigned long request, void *buffer, size_t size);
} file_ops_t;

struct file {
    object_t base;
    dentry_t *path;
    inode_t *inode;
    mutex_t lock;
    uint64_t position;
    int flags;
};

typedef struct {
    hydrogen_ret_t (*tmpfile)(filesystem_t *fs, struct ident *ident, uint32_t mode);
} fs_ops_t;

struct filesystem {
    const fs_ops_t *ops;
    uint64_t id;
    dentry_t *mountpoint;
    dentry_t *root;
    size_t block_size;
    uint32_t flags;
};

typedef struct fs_device fs_device_t;

typedef struct {
    void (*free)(fs_device_t *self);
    hydrogen_ret_t (*open)(fs_device_t *self, inode_t *inode, dentry_t *path, int flags, struct ident *ident);
} fs_device_ops_t;

typedef struct fs_device {
    const fs_device_ops_t *ops;
    refcnt_t references;
} fs_device_t;

typedef struct {
    void (*free)(inode_t *self);
    int (*chmodown)(inode_t *self, uint32_t mode, uint32_t uid, uint32_t gid);
    int (*utime)(inode_t *self, __int128_t atime, __int128_t ctime, __int128_t mtime);
    union {
        struct {
            hydrogen_ret_t (*open)(inode_t *self, dentry_t *path, int flags);
            int (*lookup)(inode_t *self, dentry_t *entry);
            int (*create)(
                inode_t *self,
                dentry_t *entry,
                hydrogen_file_type_t type,
                struct ident *ident,
                uint32_t mode,
                fs_device_t *device
            );
            int (*symlink)(inode_t *self, dentry_t *entry, const void *target, size_t size, struct ident *ident);
            int (*link)(inode_t *self, dentry_t *entry, inode_t *target);
            int (*unlink)(inode_t *self, dentry_t *entry);
            int (*rename)(inode_t *self, dentry_t *entry, inode_t *target, dentry_t *target_entry);
        } directory;
        struct {
            int (*truncate)(inode_t *self, uint64_t size);
        } regular;
        struct {
            int (*readlink)(inode_t *self);
        } symlink;
    };
} inode_ops_t;

struct inode {
    const inode_ops_t *ops;
    refcnt_t references;
    filesystem_t *fs;
    uint64_t id;

    mutex_t lock;
    uint64_t links;
    uint64_t blocks;
    uint64_t size;
    __int128_t atime;
    __int128_t btime;
    __int128_t ctime;
    __int128_t mtime;
    hydrogen_file_type_t type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;

    union {
        void *symlink;
        mem_object_t *regular;
        fs_device_t *device;
        fifo_t fifo;
    };
};

INIT_DECLARE(vfs);

// inode must be locked
int access_inode(inode_t *inode, struct ident *ident, uint32_t type, bool use_real);

int vfs_mount(file_t *file, const void *path, size_t length, filesystem_t *fs);

int vfs_chdir(struct process *process, file_t *file, const void *path, size_t length);
int vfs_fchdir(struct process *process, file_t *file);
int vfs_chroot(struct process *process, file_t *file, const void *path, size_t length);
int vfs_fchroot(struct process *process, file_t *file);
uint32_t vfs_umask(struct process *process, uint32_t mask);

int vfs_create(
    file_t *rel,
    const void *path,
    size_t length,
    hydrogen_file_type_t type,
    uint32_t mode,
    fs_device_t *device
);
int vfs_symlink(file_t *rel, const void *path, size_t length, const void *tpath, size_t tlength);
int vfs_link(file_t *rel, const void *path, size_t length, file_t *trel, const void *tpath, size_t tlength, int flags);
int vfs_unlink(file_t *rel, const void *path, size_t length, int flags);
int vfs_rename(file_t *rel, const void *path, size_t length, file_t *trel, const void *tpath, size_t tlength);

int vfs_access(file_t *rel, const void *path, size_t length, uint32_t type, int flags);
int vfs_stat(file_t *rel, const void *path, size_t length, hydrogen_file_information_t *out, int flags);
int vfs_fstat(file_t *file, hydrogen_file_information_t *out);
hydrogen_ret_t vfs_readlink(file_t *rel, const void *path, size_t length, void *buffer, size_t size);
int vfs_chmod(file_t *rel, const void *path, size_t length, uint32_t mode, int flags);
int vfs_fchmod(file_t *file, uint32_t mode);
int vfs_chown(file_t *rel, const void *path, size_t length, uint32_t uid, uint32_t gid, int flags);
int vfs_fchown(file_t *file, uint32_t uid, uint32_t gid);
int vfs_utime(
    file_t *rel,
    const void *path,
    size_t length,
    __int128_t atime,
    __int128_t ctime,
    __int128_t mtime,
    int flags
);
int vfs_futime(file_t *file, __int128_t atime, __int128_t ctime, __int128_t mtime);
int vfs_truncate(file_t *rel, const void *path, size_t length, uint64_t size);
int vfs_ftruncate(file_t *file, uint64_t size);

int vfs_open(file_t **out, file_t *rel, const void *path, size_t length, int flags, uint32_t mode, ident_t *ident);
int vfs_fopen(file_t **out, dentry_t *path, inode_t *inode, int flags, ident_t *ident);
hydrogen_ret_t vfs_mmap(
    file_t *file,
    object_rights_t rights,
    struct vmm *vmm,
    uintptr_t hint,
    size_t size,
    uint32_t flags,
    uint64_t offset
);
hydrogen_ret_t vfs_pread(file_t *file, void *buffer, size_t size, uint64_t position);
hydrogen_ret_t vfs_pwrite(file_t *file, const void *buffer, size_t size, uint64_t position);
hydrogen_ret_t vfs_seek(file_t *file, hydrogen_seek_anchor_t anchor, int64_t offset);
hydrogen_ret_t vfs_read(file_t *file, void *buffer, size_t size);
hydrogen_ret_t vfs_readdir(file_t *file, void *buffer, size_t size);
hydrogen_ret_t vfs_write(file_t *file, const void *buffer, size_t size);
hydrogen_ret_t vfs_ioctl(file_t *file, unsigned long request, void *buffer, size_t size);

int vfs_fflags(file_t *file, int flags);
hydrogen_ret_t vfs_fpath(dentry_t *path, void **buf_out, size_t *len_out);

void dentry_ref(dentry_t *entry);
void dentry_deref(dentry_t *entry);
void inode_ref(inode_t *inode);
void inode_deref(inode_t *inode);
void fsdev_ref(fs_device_t *dev);
void fsdev_deref(fs_device_t *dev);

uint64_t get_next_fs_id(void);
void init_new_inode(inode_t *directory, inode_t *inode, ident_t *ident, uint32_t mode);

int create_root_dentry(filesystem_t *fs, inode_t *root);
void init_file(file_t *file, const file_ops_t *ops, inode_t *inode, dentry_t *path, int flags);
void free_file(file_t *file);

int vfs_create_anonymous(inode_t **out, hydrogen_file_type_t type, uint32_t mode, fs_device_t *device, ident_t *ident);

static inline int vfs_pwrite_full(file_t *file, const void *data, size_t size, uint64_t position) {
    while (size) {
        hydrogen_ret_t ret = vfs_pwrite(file, data, size, position);
        if (unlikely(ret.error)) return ret.error;

        data += ret.integer;
        size -= ret.integer;
        position += ret.integer;
    }

    return 0;
}

int deny_chmodown(inode_t *self, uint32_t mode, uint32_t uid, uint32_t gid);
int deny_utime(inode_t *self, __int128_t atime, __int128_t ctime, __int128_t mtime);
int deny_create(
    inode_t *self,
    dentry_t *entry,
    hydrogen_file_type_t type,
    struct ident *ident,
    uint32_t mode,
    fs_device_t *device
);
int deny_symlink(inode_t *self, dentry_t *entry, const void *target, size_t size, struct ident *ident);
int deny_link(inode_t *self, dentry_t *entry, inode_t *target);
int deny_unlink(inode_t *self, dentry_t *entry);
int deny_rename(inode_t *self, dentry_t *entry, inode_t *target, dentry_t *target_entry);

static inline hydrogen_ret_t emit_single_dirent(
    void **buffer,
    size_t *size,
    uint64_t id,
    uint64_t position,
    hydrogen_file_type_t type,
    const void *name,
    size_t length
) {
    size_t offset = offsetof(hydrogen_directory_entry_t, name);
    size_t cursz = offset + length;
    // align cursz+1 up
    size_t totsz = (cursz + _Alignof(hydrogen_directory_entry_t)) & ~(_Alignof(hydrogen_directory_entry_t) - 1);
    if (totsz > *size) return ret_integer(0);

    hydrogen_directory_entry_t base_entry = {.id = id, .position = position, .size = totsz, .type = type};

    int error = user_memcpy(*buffer, &base_entry, offset);
    if (unlikely(error)) return ret_error(error);
    *buffer += offset;
    *size -= offset;

    error = user_memcpy(*buffer, name, length);
    if (unlikely(error)) return ret_error(error);
    *buffer += length;
    *size -= length;

    size_t padding = totsz - cursz;
    error = user_memset(*buffer, 0, padding);
    if (unlikely(error)) return ret_error(error);
    *buffer += padding;
    *size -= padding;

    return ret_integer(totsz);
}
