#include "arch/memmap.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "errno.h"
#include "fs/vfs.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/kvmm.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "string.h"
#include "util/handle.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/refcount.h"
#include <hydrogen/fcntl.h>
#include <hydrogen/filesystem.h>
#include <hydrogen/handle.h>
#include <hydrogen/memory.h>
#include <hydrogen/types.h>
#include <stddef.h>
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

static hydrogen_ret_t mem_seek(file_t *self, hydrogen_seek_anchor_t anchor, int64_t offset) {
    uint64_t position;

    switch (anchor) {
    case HYDROGEN_SEEK_BEGIN: position = 0; break;
    case HYDROGEN_SEEK_CURRENT: position = self->position; break;
    default: return ret_error(EINVAL);
    }

    uint64_t rpos = position + offset;

    if (offset >= 0) {
        if (rpos < position || rpos > INT64_MAX) return ret_error(EOVERFLOW);
    } else if (rpos > position) {
        return ret_error(EINVAL);
    }

    return ret_integer(rpos);
}

#define MEM_OWNED (1 << 0)
#define MEM_RAM (1 << 1)

struct mem_iter_ctx {
    int (*cb)(uint64_t, uint64_t, int, void *);
    void *ctx;
    uint64_t position;
    uint64_t end;
    int error;
};

static bool mem_handle_area(uint64_t head, uint64_t tail, int flags, struct mem_iter_ctx *ctx) {
    if (head >= ctx->end) return false;
    if (tail >= ctx->end) tail = ctx->end - 1;

    int error = ctx->cb(head, tail, flags, ctx->ctx);

    if (unlikely(error)) {
        ctx->error = error;
        return false;
    }

    ctx->position = tail + 1;
    return ctx->position < ctx->end;
}

static bool mem_iter_cb(uint64_t head, uint64_t tail, bool owned, void *ptr) {
    struct mem_iter_ctx *ctx = ptr;

    if (ctx->position < head && !mem_handle_area(ctx->position, head - 1, 0, ctx)) return false;

    int flags = MEM_RAM;
    if (owned) flags |= MEM_OWNED;
    return mem_handle_area(head, tail, flags, ctx);
}

static hydrogen_ret_t mem_iter(uint64_t start, size_t count, int (*cb)(uint64_t, uint64_t, int, void *), void *ctx) {
    uint64_t end = start + count;
    if (end < start || end > INT64_MAX) end = INT64_MAX;
    if (end <= start) return ret_integer(0);

    struct mem_iter_ctx data = {cb, ctx, start, end, 0};

    if (memmap_iter(mem_iter_cb, &data) && data.position < end) {
        uint64_t tail = cpu_max_phys_addr();
        if (data.position <= tail) mem_handle_area(data.position, tail, 0, &data);
    }

    return RET_MAYBE(integer, data.error, data.position - start);
}

struct mem_read_ctx {
    void *buffer;
    uint64_t start;
};

static int mem_read_cb(uint64_t head, uint64_t tail, int flags, void *ptr) {
    struct mem_read_ctx *ctx = ptr;
    void *buffer = ctx->buffer + (head - ctx->start);
    size_t count = tail - head + 1;

    if (flags & MEM_OWNED) return user_memset(buffer, 0, count);

    unsigned pflag = PMAP_READABLE;
    if ((flags & MEM_RAM) == 0) pflag |= PMAP_CACHE_UC;

    uintptr_t addr;
    int error = map_mmio(&addr, head, count, pflag);
    if (unlikely(error)) return error;

    error = user_memcpy(buffer, (const void *)ptr, count);
    unmap_mmio(addr, count);
    return error;
}

static hydrogen_ret_t mem_read(file_t *self, void *buffer, size_t size, uint64_t position) {
    struct mem_read_ctx ctx = {buffer, position};
    return mem_iter(position, size, mem_read_cb, &ctx);
}

struct mem_write_ctx {
    const void *buffer;
    uint64_t start;
};

static int mem_write_cb(uint64_t head, uint64_t tail, int flags, void *ptr) {
    struct mem_write_ctx *ctx = ptr;
    const void *buffer = ctx->buffer + (head - ctx->start);
    size_t count = tail - head + 1;

    if (flags & MEM_OWNED) return 0;

    unsigned pflag = PMAP_WRITABLE;
    if ((flags & MEM_RAM) == 0) pflag |= PMAP_CACHE_UC;

    uintptr_t addr;
    int error = map_mmio(&addr, head, count, pflag);
    if (unlikely(error)) return error;

    error = user_memcpy((void *)ptr, buffer, count);
    unmap_mmio(addr, count);
    return error;
}

static hydrogen_ret_t mem_write(file_t *self, const void *buffer, size_t size, uint64_t position, bool rpos) {
    struct mem_write_ctx ctx = {buffer, position};
    return mem_iter(position, size, mem_write_cb, &ctx);
}

struct mem_map_ctx {
    vmm_t *vmm;
    uintptr_t vhead;
    uint64_t phead;
    unsigned flags;
};

static int mem_map_cb(uint64_t head, uint64_t tail, int flags, void *ptr) {
    if (flags & MEM_OWNED) return 0;

    struct mem_map_ctx *ctx = ptr;
    pmap_map(ctx->vmm, ctx->vhead + (head - ctx->phead), head, tail - head + 1, ctx->flags);
    return 0;
}

static void mem_object_map(
    mem_object_t *self,
    vmm_t *vmm,
    uintptr_t head,
    uintptr_t tail,
    unsigned flags,
    uint64_t offset
) {
    struct mem_map_ctx ctx = {.vmm = vmm, .vhead = head, .phead = offset};

    if (flags & HYDROGEN_MEM_READ) flags |= PMAP_READABLE;
    if (flags & HYDROGEN_MEM_WRITE) flags |= PMAP_WRITABLE;
    if (flags & HYDROGEN_MEM_EXEC) flags |= PMAP_EXECUTABLE;

    // TODO: Add better memory type pmap flags.
    switch (flags & HYDROGEN_MEM_TYPE_MASK) {
    case HYDROGEN_MEM_TYPE_NORMAL: flags |= PMAP_CACHE_WB; break;
    case HYDROGEN_MEM_TYPE_DEVICE: flags |= PMAP_CACHE_WC; break;
    default: flags |= PMAP_CACHE_UC; break;
    }

    mem_iter(offset, tail - head + 1, mem_map_cb, &ctx);
}

static const mem_object_ops_t mem_object_ops = {.mem_type_allowed = true, .post_map = mem_object_map};
static mem_object_t mem_object = {.base.ops = &mem_object_ops.base, .base.references = REF_INIT(1)};

static hydrogen_ret_t mem_mmap(
    file_t *self,
    object_rights_t rights,
    struct vmm *vmm,
    uintptr_t hint,
    size_t size,
    uint32_t flags,
    uint64_t offset
) {
    return vmm_map(vmm, hint, size, flags, &mem_object, rights, offset);
}

static const file_ops_t mem_ops = {
    .base.free = special_file_free,
    .seek = mem_seek,
    .read = mem_read,
    .write = mem_write,
    .mmap = mem_mmap,
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
        uint32_t mode;
    } devices[] = {
        {"/dev/null", &null_ops, 0666},
        {"/dev/zero", &zero_ops, 0666},
        {"/dev/full", &full_ops, 0666},
        {"/dev/mem", &mem_ops, 0600},
    };
    static special_device_t device_objects[sizeof(devices) / sizeof(*devices)];
    static stream_device_t stream_devices[3];
    static const char *stream_device_names[3] = {"/dev/stdin", "/dev/stdout", "/dev/stderr"};

    mem_object_init(&mem_object);

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
            devices[i].mode,
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
