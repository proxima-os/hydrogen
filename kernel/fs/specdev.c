#include "arch/memmap.h"
#include "arch/pmap.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/kvmm.h"
#include "mem/memmap.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
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
#include <hydrogen/ioctl-data.h>
#include <hydrogen/ioctl.h>
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
    if (tail < ctx->position) return true;
    if (head < ctx->position) head = ctx->position;
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
    struct mem_map_ctx ctx = {.vmm = vmm, .vhead = head, .phead = offset, .flags = vmm_to_pmap_flags(flags)};
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

typedef struct {
    fs_device_t base;
    mem_object_t mem;
    page_t *head;
    size_t count;
    bool have_mem_ref;
} alloc_device_t;

static hydrogen_ret_t alloc_seek(file_t *self, hydrogen_seek_anchor_t anchor, int64_t offset) {
    alloc_device_t *device = (alloc_device_t *)self->inode->device;
    uint64_t position;

    switch (anchor) {
    case HYDROGEN_SEEK_BEGIN: position = 0; break;
    case HYDROGEN_SEEK_CURRENT: position = self->position; break;
    case HYDROGEN_SEEK_END: position = (uint64_t)device->count << PAGE_SHIFT; break;
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

static hydrogen_ret_t alloc_read(file_t *self, void *buffer, size_t count, uint64_t position) {
    alloc_device_t *device = (alloc_device_t *)self->inode->device;
    uint64_t size = (uint64_t)device->count << PAGE_SHIFT;
    if (size > INT64_MAX) size = INT64_MAX;
    if (position >= size) return ret_integer(0);
    uint64_t avail = size - position;

    size_t cur = avail < count ? avail : count;
    int error = user_memcpy(buffer, page_to_virt(device->head) + position, cur);
    return RET_MAYBE(integer, error, cur);
}

static hydrogen_ret_t alloc_write(file_t *self, const void *buffer, size_t count, uint64_t position, bool rpos) {
    alloc_device_t *device = (alloc_device_t *)self->inode->device;
    uint64_t size = (uint64_t)device->count << PAGE_SHIFT;
    if (size > INT64_MAX) size = INT64_MAX;
    if (position >= size) return ret_integer(0);
    uint64_t avail = size - position;

    size_t cur = avail < count ? avail : count;
    int error = user_memcpy(page_to_virt(device->head) + position, buffer, cur);
    return RET_MAYBE(integer, error, cur);
}

static hydrogen_ret_t alloc_mmap(
    file_t *self,
    object_rights_t rights,
    struct vmm *vmm,
    uintptr_t hint,
    size_t size,
    uint32_t flags,
    uint64_t offset
) {
    alloc_device_t *device = (alloc_device_t *)self->inode->device;
    return vmm_map(vmm, hint, size, flags, &device->mem, rights, offset);
}

static const file_ops_t alloc_file_ops = {
    .base.free = special_file_free,
    .seek = alloc_seek,
    .read = alloc_read,
    .write = alloc_write,
    .mmap = alloc_mmap,
};

static void alloc_device_free(fs_device_t *ptr) {
    alloc_device_t *self = (alloc_device_t *)ptr;
    pmem_free_multiple_now(self->head, self->count);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t alloc_device_open(fs_device_t *self, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

    init_file(file, &alloc_file_ops, inode, path, flags);

    return ret_pointer(file);
}

static void alloc_device_mem_free(object_t *ptr) {
    alloc_device_t *self = CONTAINER(alloc_device_t, mem.base, ptr);

    if (__atomic_exchange_n(&self->have_mem_ref, false, __ATOMIC_ACQ_REL)) {
        fsdev_deref(&self->base);
    }
}

static void alloc_device_mem_map(
    mem_object_t *ptr,
    vmm_t *vmm,
    uintptr_t head,
    uintptr_t tail,
    unsigned flags,
    uint64_t offset
) {
    alloc_device_t *self = CONTAINER(alloc_device_t, mem, ptr);

    if (!__atomic_exchange_n(&self->have_mem_ref, true, __ATOMIC_ACQ_REL)) {
        fsdev_ref(&self->base);
    }

    uint64_t size = (uint64_t)self->count << PAGE_SHIFT;
    if (offset >= size) return;
    uint64_t avail = size - offset;
    size_t wanted = tail - head + 1;
    size_t cur = avail < wanted ? avail : wanted;

    pmap_map(vmm, head, page_to_phys(self->head) + offset, cur, vmm_to_pmap_flags(flags));
}

static const fs_device_ops_t alloc_device_ops = {
    .free = alloc_device_free,
    .open = alloc_device_open,
};

static const mem_object_ops_t alloc_device_mem_ops = {
    .base.free = alloc_device_mem_free,
    .post_map = alloc_device_mem_map,
};

static hydrogen_ret_t create_alloc_file(page_t *head, size_t count, int flags) {
    alloc_device_t *device = vmalloc(sizeof(*device));
    if (unlikely(!device)) return ret_error(ENOMEM);
    memset(device, 0, sizeof(*device));

    device->base.ops = &alloc_device_ops;
    device->base.references = REF_INIT(1);
    device->mem.base.ops = &alloc_device_mem_ops.base;
    device->head = head;
    device->count = count;

    mem_object_init(&device->mem);
    obj_deref(&device->mem.base);

    inode_t *inode;
    ident_t *ident = ident_get(current_thread->process);
    int error = vfs_create_anonymous(&inode, HYDROGEN_CHARACTER_DEVICE, __S_IRUSR | __S_IWUSR, &device->base, ident);
    fsdev_deref(&device->base);
    if (unlikely(error)) {
        ident_deref(ident);
        return ret_error(error);
    }

    file_t *file;
    error = vfs_fopen(&file, NULL, inode, flags | __O_RDONLY | __O_WRONLY, ident);
    inode_deref(inode);
    ident_deref(ident);
    if (unlikely(error)) return ret_error(error);

    return ret_pointer(file);
}

static hydrogen_ret_t mem_ioctl(file_t *self, int request, void *buffer, size_t size) {
    switch (request) {
    case __IOCTL_MEM_ALLOCATE: {
        if (unlikely((self->flags & (__O_RDONLY | __O_WRONLY)) != (__O_RDONLY | __O_WRONLY))) {
            return ret_error(EBADF);
        }

        hydrogen_ioctl_mem_allocate_t data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        if (unlikely(data.input.min > data.input.max)) return ret_error(EINVAL);
        if (unlikely(data.input.size == 0)) return ret_error(EINVAL);
        if (unlikely(data.input.align == 0)) return ret_error(EINVAL);
        if (unlikely(data.input.align & (data.input.align - 1))) return ret_error(EINVAL);
        if (unlikely(data.input.flags & ~(__O_CLOEXEC | __O_CLOFORK))) return ret_error(EINVAL);

        uint64_t limit = data.input.size - 1;
        if (unlikely(limit > data.input.max - data.input.min)) return ret_error(EINVAL);

        uint64_t min = (data.input.min + PAGE_MASK) & ~PAGE_MASK;
        uint64_t max = (data.input.max - PAGE_MASK) | PAGE_MASK;

        if (unlikely(min < data.input.min)) return ret_error(ENOMEM);
        if (unlikely(max > data.input.max)) return ret_error(ENOMEM);
        if (unlikely(min > max)) return ret_error(ENOMEM);

        limit |= PAGE_MASK;
        if (unlikely(limit > max - min)) return ret_error(ENOMEM);
        size_t pages = (limit >> PAGE_SHIFT) + 1;

        page_t *page = pmem_alloc_slow_and_unreliable_now(min, max, data.input.align, pages);
        if (unlikely(!page)) return ret_error(ENOMEM);

        hydrogen_ret_t ret = create_alloc_file(page, pages, data.input.flags);
        if (unlikely(ret.error)) {
            pmem_free_multiple_now(page, pages);
            return ret;
        }
        file_t *file = ret.pointer;

        uint32_t handle_flags = 0;

        if (!(data.input.flags & __O_CLOEXEC)) handle_flags |= HYDROGEN_HANDLE_EXEC_KEEP;
        if (!(data.input.flags & __O_CLOFORK)) handle_flags |= HYDROGEN_HANDLE_CLONE_KEEP;

        error = hnd_reserve(current_thread->namespace);
        if (unlikely(error)) {
            obj_deref(&file->base);
            return ret_error(error);
        }

        handle_data_t *hdata = vmalloc(sizeof(*hdata));
        if (unlikely(error)) {
            hnd_unreserve(current_thread->namespace);
            obj_deref(&file->base);
            return ret_error(error);
        }

        data.output.address = page_to_phys(page);
        error = user_memcpy(buffer, &data, sizeof(data));
        if (unlikely(error)) {
            vfree(hdata, sizeof(*hdata));
            hnd_unreserve(current_thread->namespace);
            obj_deref(&file->base);
            return ret_error(error);
        }

        int fd = hnd_alloc_reserved(
            current_thread->namespace,
            &file->base,
            HYDROGEN_FILE_READ | HYDROGEN_FILE_WRITE,
            handle_flags,
            hdata
        );
        obj_deref(&file->base);
        return ret_integer(fd);
    }
    case __IOCTL_MEM_IS_RAM: {
        if (unlikely(!(self->flags & __O_RDONLY))) return ret_error(EBADF);

        hydrogen_ioctl_mem_is_ram_t data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        if (unlikely(data.size == 0)) return ret_error(EINVAL);

        uint64_t tail = data.start + (data.size - 1);
        if (tail < data.start) tail = UINT64_MAX;

        return ret_integer(is_area_ram(data.start, tail));
    }
    case __IOCTL_MEM_NEXT_RAM_RANGE: {
        if (unlikely(!(self->flags & __O_RDONLY))) return ret_error(EBADF);

        hydrogen_ioctl_mem_next_ram_range_t data;
        if (unlikely(size < sizeof(data))) return ret_error(EINVAL);

        int error = user_memcpy(&data, buffer, sizeof(data));
        if (unlikely(error)) return ret_error(error);

        uint64_t head, tail;
        bool owned;
        if (!next_ram_range(data.input.address, &head, &tail, &owned)) return ret_error(ENOENT);

        data.output.start = head;
        data.output.size = tail - head + 1;
        data.output.kernel_owned = owned;

        return ret_error(user_memcpy(buffer, &data, sizeof(data)));
    }
    default: return ret_error(ENOTTY);
    }
}

static const file_ops_t mem_ops = {
    .base.free = special_file_free,
    .seek = mem_seek,
    .read = mem_read,
    .write = mem_write,
    .mmap = mem_mmap,
    .ioctl = mem_ioctl,
};

typedef struct {
    fs_device_t base;
    const file_ops_t *ops;
} special_device_t;

static hydrogen_ret_t special_device_open(fs_device_t *ptr, inode_t *inode, dentry_t *path, int flags, ident_t *ident) {
    special_device_t *self = (special_device_t *)ptr;
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

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
