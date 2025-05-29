#include "arch/usercopy.h"
#include "errno.h"
#include "fs/vfs.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "string.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/refcount.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/types.h>
#include <stdint.h>

static void special_file_free(object_t *ptr) {
    file_t *self = (file_t *)ptr;
    free_file(self);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t special_file_seek(file_t *self, hydrogen_seek_anchor_t anchor, int64_t offset) {
    return ret_integer(0);
}

static hydrogen_ret_t null_read(file_t *self, void *buffer, size_t count, uint64_t position) {
    return ret_integer(0);
}

static hydrogen_ret_t null_write(file_t *self, const void *buffer, size_t count, uint64_t position, bool rpos) {
    return ret_integer(count);
}

static hydrogen_ret_t zero_read(file_t *self, void *buffer, size_t count, uint64_t position) {
    int error = user_memset(buffer, 0, count);
    if (unlikely(error)) return ret_error(error);
    return ret_integer(count);
}

static hydrogen_ret_t full_write(file_t *self, const void *buffer, size_t count, uint64_t position, bool rpos) {
    return ret_error(ENOSPC);
}

static const file_ops_t null_ops = {
    .base.free = special_file_free,
    .seek = special_file_seek,
    .read = null_read,
    .write = null_write,
};

static const file_ops_t zero_ops = {
    .base.free = special_file_free,
    .seek = special_file_seek,
    .read = zero_read,
    .write = null_write,
};

static const file_ops_t full_ops = {
    .base.free = special_file_free,
    .seek = special_file_seek,
    .read = zero_read,
    .write = full_write,
};

typedef struct {
    fs_device_t base;
    const file_ops_t *ops;
} special_device_t;

static hydrogen_ret_t special_device_open(fs_device_t *ptr, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    special_device_t *self = (special_device_t *)ptr;
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);

    init_file(file, self->ops, inode, path, flags);
    return ret_pointer(file);
}

static const fs_device_ops_t special_device_ops = {.open = special_device_open};

typedef struct {
    fs_device_t base;
    int stream;
} stream_device_t;

static hydrogen_ret_t stream_device_open(fs_device_t *ptr, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    stream_device_t *self = (stream_device_t *)ptr;

    handle_data_t data;
    int error = hnd_resolve(&data, self->stream, OBJECT_FILE_DESCRIPTION, 0);
    if (unlikely(error)) return ret_error(error == EBADF ? EEXIST : 0);
    file_t *file = (file_t *)data.object;

    file_t *ret;
    error = vfs_fopen(&ret, file->path, file->inode, flags, ident);
    obj_deref(&file->base);
    if (unlikely(error)) return ret_error(error);

    return ret_pointer(ret);
}

static const fs_device_ops_t stream_device_ops = {.open = stream_device_open};

static void create_special_devices(void) {
    static struct {
        const char *name;
        const file_ops_t *ops;
    } devices[] = {
        {"/dev/null", &null_ops},
        {"/dev/zero", &zero_ops},
        {"/dev/full", &full_ops},
    };
    static special_device_t device_objects[sizeof(devices) / sizeof(*devices)];
    static stream_device_t stream_devices[3];
    static const char *stream_device_names[3] = {"/dev/stdin", "/dev/stdout", "/dev/stderr"};

    for (size_t i = 0; i < sizeof(devices) / sizeof(*devices); i++) {
        special_device_t *dev = &device_objects[i];
        dev->base.ops = &special_device_ops;
        dev->base.references = REF_INIT(1);
        dev->ops = devices[i].ops;

        int error = vfs_create(
            NULL,
            devices[i].name,
            strlen(devices[i].name),
            HYDROGEN_CHARACTER_DEVICE,
            0666,
            &dev->base
        );
        if (unlikely(error)) panic("failed to create %s (%e)", devices[i].name, error);
    }

    for (size_t i = 0; i < sizeof(stream_devices) / sizeof(*stream_devices); i++) {
        stream_devices[i].base.ops = &stream_device_ops;
        stream_devices[i].base.references = REF_INIT(1);
        stream_devices[i].stream = i;

        int error = vfs_create(
            NULL,
            stream_device_names[i],
            strlen(stream_device_names[i]),
            HYDROGEN_CHARACTER_DEVICE,
            0777,
            &stream_devices[i].base
        );
        if (unlikely(error)) panic("failed to create %s (%e)", stream_device_names[i], error);
    }
}

INIT_DEFINE(create_special_devices, create_special_devices, INIT_REFERENCE(mount_rootfs));
