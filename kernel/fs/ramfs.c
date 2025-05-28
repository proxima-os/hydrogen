#include "fs/ramfs.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "hydrogen/filesystem.h"
#include "hydrogen/memory.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/object/anonymous.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "string.h"
#include "util/list.h"
#include "util/object.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    filesystem_t base;
    uint64_t next_id;
} ramfs_fs_t;

typedef struct {
    inode_t base;
    anon_mem_object_t data;
    const mem_object_ops_t *orig_data_ops;
    bool have_data_ref;
} ramfs_inode_t;

static void ramfs_inode_free(inode_t *ptr) {
    ramfs_inode_t *self = (ramfs_inode_t *)ptr;
    vfree(self, sizeof(*self));
}

static int ramfs_inode_chmodown(inode_t *ptr, uint32_t mode, uint32_t uid, uint32_t gid) {
    ptr->mode = mode;
    ptr->uid = uid;
    ptr->gid = gid;
    ptr->ctime = get_current_timestamp();
    return 0;
}

static int ramfs_inode_utime(inode_t *ptr, __int128_t atime, __int128_t ctime, __int128_t mtime) {
    __int128_t now = get_current_timestamp();

    if (atime != HYDROGEN_FILE_TIME_OMIT) {
        ptr->atime = atime == HYDROGEN_FILE_TIME_NOW ? now : atime;
    }

    if (ctime != HYDROGEN_FILE_TIME_OMIT) {
        ptr->ctime = ctime == HYDROGEN_FILE_TIME_NOW ? now : ctime;
    }

    if (mtime != HYDROGEN_FILE_TIME_OMIT) {
        ptr->mtime = mtime == HYDROGEN_FILE_TIME_NOW ? now : mtime;
    }

    return 0;
}

static void ramfs_inode_regular_free(inode_t *ptr) {
    ramfs_inode_t *self = (ramfs_inode_t *)ptr;
    self->orig_data_ops->base.free(&self->data.base.base);
}

static int ramfs_inode_regular_truncate(inode_t *ptr, uint64_t size) {
    ramfs_inode_t *self = (ramfs_inode_t *)ptr;

    uint64_t pages = (size + PAGE_MASK) >> PAGE_SHIFT;

    int error = anon_mem_object_resize(&self->data.base, pages);
    if (unlikely(error)) return error;

    self->base.size = size;
    self->base.blocks = pages;
    self->base.ctime = get_current_timestamp();
    self->base.mtime = self->base.ctime;

    return 0;
}

static void ramfs_inode_regular_data_free(object_t *ptr) {
    ramfs_inode_t *self = CONTAINER(ramfs_inode_t, data.base.base, ptr);
    mutex_acq(&self->base.lock, 0, false);

    if (!self->have_data_ref) {
        self->have_data_ref = false;
        inode_deref(&self->base);
    }

    mutex_rel(&self->base.lock);
}

static hydrogen_ret_t ramfs_inode_regular_data_get_page(
        mem_object_t *ptr,
        vmm_region_t *region,
        uint64_t index,
        rcu_state_t *state_out,
        bool write
) {
    ramfs_inode_t *self = CONTAINER(ramfs_inode_t, data.base, ptr);

    if (region != NULL) {
        mutex_acq(&self->base.lock, 0, false);

        self->base.atime = get_current_timestamp();

        if (write && (region->flags & HYDROGEN_MEM_SHARED) != 0) {
            self->base.ctime = self->base.atime;
            self->base.mtime = self->base.atime;
        }

        mutex_rel(&self->base.lock);
    }

    return self->orig_data_ops->get_page(ptr, region, index, state_out, write);
}

static void ramfs_inode_regular_data_post_map(
        mem_object_t *ptr,
        vmm_t *vmm,
        uintptr_t head,
        uintptr_t tail,
        unsigned flags,
        uint64_t offset
) {
    ramfs_inode_t *self = CONTAINER(ramfs_inode_t, data.base, ptr);
    mutex_acq(&self->base.lock, 0, false);

    if (!self->have_data_ref) {
        inode_ref(&self->base);
        self->have_data_ref = true;
    }

    mutex_rel(&self->base.lock);
}

static const inode_ops_t ramfs_inode_special_ops = {
        .free = ramfs_inode_free,
        .chmodown = ramfs_inode_chmodown,
        .utime = ramfs_inode_utime,
};
static const inode_ops_t ramfs_inode_regular_ops = {
        .free = ramfs_inode_regular_free,
        .chmodown = ramfs_inode_chmodown,
        .utime = ramfs_inode_utime,
        .regular.truncate = ramfs_inode_regular_truncate,
};
static const inode_ops_t ramfs_inode_directory_ops;
static const mem_object_ops_t ramfs_inode_regular_data_ops = {
        .base.free = ramfs_inode_regular_data_free,
        .get_page = ramfs_inode_regular_data_get_page,
        .post_map = ramfs_inode_regular_data_post_map,
};

static int create_ramfs_inode(
        ramfs_fs_t *fs,
        inode_t *dir,
        inode_t **out,
        hydrogen_file_type_t type,
        ident_t *ident,
        uint32_t mode,
        fs_device_t *device
) {
    ramfs_inode_t *inode = vmalloc(sizeof(*inode));
    if (unlikely(!inode)) return ENOMEM;
    memset(inode, 0, sizeof(*inode));

    inode->base.fs = &fs->base;
    inode->base.type = type;
    inode->base.id = __atomic_fetch_add(&fs->next_id, 1, __ATOMIC_RELAXED);

    switch (type) {
    case HYDROGEN_REGULAR_FILE:
        inode->base.ops = &ramfs_inode_regular_ops;
        int error = anon_mem_object_init(&inode->data, 0);
        if (unlikely(error)) {
            vfree(inode, sizeof(*inode));
            return 0;
        }
        inode->orig_data_ops = (const mem_object_ops_t *)inode->data.base.base.ops;
        inode->data.base.base.ops = &ramfs_inode_regular_data_ops.base;
        obj_deref(&inode->data.base.base);
        inode->base.regular = &inode->data.base;
        break;
    case HYDROGEN_DIRECTORY: inode->base.ops = &ramfs_inode_directory_ops; break;
    case HYDROGEN_CHARACTER_DEVICE:
    case HYDROGEN_BLOCK_DEVICE: inode->base.device = device; fsdev_ref(device); // fall through
    default: inode->base.ops = &ramfs_inode_special_ops; break;
    }

    init_new_inode(dir, &inode->base, ident, mode);

    *out = &inode->base;
    return 0;
}

static void ramfs_file_dir_free(object_t *ptr) {
    file_t *file = (file_t *)ptr;
    free_file(file);
    vfree(file, sizeof(*file));
}

static hydrogen_ret_t ramfs_file_dir_seek(file_t *ptr, hydrogen_seek_anchor_t anchor, int64_t offset) {
    uint64_t position;

    switch (anchor) {
    case HYDROGEN_SEEK_BEGIN: position = 0; break;
    case HYDROGEN_SEEK_CURRENT: position = ptr->position; break;
    case HYDROGEN_SEEK_END:
        mutex_acq(&ptr->path->lock, 0, false);
        position = ptr->path->real_count + 2;
        mutex_rel(&ptr->path->lock);
        break;
    default: return ret_error(EINVAL);
    }

    uint64_t base = position;
    position += (uint64_t)offset;

    if (offset >= 0) {
        if (position < base || position > INT64_MAX) return ret_error(EOVERFLOW);
    } else if (position > base) {
        return ret_error(EINVAL);
    }

    return ret_integer(position);
}

static hydrogen_ret_t emit_single(
        void **buffer,
        size_t *size,
        uint64_t id,
        hydrogen_file_type_t type,
        const void *name,
        size_t length
) {
    size_t offset = offsetof(hydrogen_directory_entry_t, name);
    size_t cursz = offset + length;
    // align cursz+1 up
    size_t totsz = (cursz + _Alignof(hydrogen_directory_entry_t)) & ~(_Alignof(hydrogen_directory_entry_t) - 1);
    if (totsz > *size) return ret_integer(0);

    hydrogen_directory_entry_t base_entry = {.size = totsz, .id = id, .name_length = length, .type = type};

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

static hydrogen_ret_t ramfs_file_dir_readdir(file_t *ptr, void *buffer, size_t size) {
    dentry_t *entry = ptr->path;
    mutex_acq(&entry->lock, 0, false);

    if (entry->inode == NULL) {
        mutex_rel(&entry->lock);
        return ret_integer(0);
    }

    dentry_t *current = LIST_HEAD(entry->child_list, dentry_t, list_node);

    for (uint64_t i = 2; current != NULL && i < ptr->position; i++) {
        current = LIST_NEXT(*current, dentry_t, list_node);
    }

    size_t total = 0;

    do {
        uint64_t id;
        hydrogen_file_type_t type;
        const void *name;
        size_t length;

        if (ptr->position == 0) {
            id = ptr->inode->id;
            type = ptr->inode->type;
            name = ".";
            length = 1;
        } else if (ptr->position == 1) {
            rcu_state_t state = rcu_read_lock();
            dentry_t *root = rcu_read(current_thread->process->root_dir);
            dentry_ref(root);
            rcu_read_unlock(state);

            dentry_t *parent = current;

            for (dentry_t *cur = entry; cur != root; cur = cur->fs->mountpoint) {
                if (cur->parent != NULL) {
                    parent = cur->parent;
                    break;
                }
            }

            id = parent->inode->id;
            type = parent->inode->type;
            name = "..";
            length = 2;
        } else {
            if (!current) break;
            if (!current->inode) continue;
            id = current->inode->id;
            type = current->inode->type;
            name = current->name.data;
            length = current->name.size;
            current = LIST_NEXT(*current, dentry_t, list_node);
        }

        hydrogen_ret_t ret = emit_single(&buffer, &size, id, type, name, length);
        if (unlikely(ret.error)) {
            if (total != 0) break;
            mutex_rel(&entry->lock);
            return ret;
        }

        if (ret.integer == 0) {
            if (total != 0) break;
            mutex_rel(&entry->lock);
            return ret_error(EINVAL);
        }

        total += ret.integer;
        ptr->position += 1;
    } while (size > 0);

    mutex_rel(&entry->lock);
    return ret_integer(total);
}

static const file_ops_t ramfs_file_dir_ops = {
        .base.free = ramfs_file_dir_free,
        .seek = ramfs_file_dir_seek,
        .readdir = ramfs_file_dir_readdir,
};

static hydrogen_ret_t ramfs_inode_directory_open(inode_t *ptr, dentry_t *path, int flags) {
    file_t *file = vmalloc(sizeof(*file));
    if (unlikely(!file)) return ret_error(ENOMEM);
    memset(file, 0, sizeof(*file));

    init_file(file, &ramfs_file_dir_ops, ptr, path, flags);

    return ret_pointer(file);
}

static int ramfs_inode_directory_lookup(inode_t *ptr, dentry_t *entry) {
    return ENOENT;
}

static int ramfs_inode_directory_create(
        inode_t *ptr,
        dentry_t *entry,
        hydrogen_file_type_t type,
        ident_t *ident,
        uint32_t mode,
        fs_device_t *device
) {
    inode_t *inode;
    int error = create_ramfs_inode((ramfs_fs_t *)ptr->fs, ptr, &inode, type, ident, mode, device);
    if (unlikely(error)) return error;

    inode->links += 1;
    entry->inode = inode;

    if (type == HYDROGEN_DIRECTORY) ptr->links += 1;
    ptr->ctime = get_current_timestamp();
    ptr->mtime = ptr->ctime;

    dentry_ref(entry);
    return 0;
}

static int ramfs_inode_directory_symlink(
        inode_t *ptr,
        dentry_t *entry,
        const void *target,
        size_t length,
        ident_t *ident
) {
    void *buffer = vmalloc(length);
    if (unlikely(!buffer)) return ENOMEM;
    memcpy(buffer, target, length);

    inode_t *inode;
    int error = create_ramfs_inode((ramfs_fs_t *)ptr->fs, ptr, &inode, HYDROGEN_SYMLINK, ident, 0777, NULL);
    if (unlikely(error)) {
        vfree(buffer, length);
        return error;
    }

    inode->symlink = buffer;
    inode->size = length;

    inode->links += 1;
    entry->inode = inode;

    ptr->ctime = get_current_timestamp();
    ptr->mtime = ptr->ctime;

    dentry_ref(entry);
    return 0;
}

static int ramfs_inode_directory_link(inode_t *ptr, dentry_t *entry, inode_t *target) {
    entry->inode = target;
    target->links += 1;

    ptr->ctime = get_current_timestamp();
    ptr->mtime = ptr->ctime;

    dentry_ref(entry);
    return 0;
}

static int ramfs_inode_directory_unlink(inode_t *ptr, dentry_t *entry) {
    __int128_t time = get_current_timestamp();

    if (entry->inode->type == HYDROGEN_DIRECTORY) {
        entry->inode->links = 0;
        ptr->links -= 1;
    } else {
        entry->inode->links -= 1;
    }

    entry->inode->ctime = time;
    inode_deref(entry->inode);
    entry->inode = NULL;

    ptr->ctime = time;
    ptr->mtime = time;

    dentry_deref(entry);
    return 0;
}

static int ramfs_inode_directory_rename(inode_t *srcdir, dentry_t *sentry, inode_t *dstdir, dentry_t *dentry) {
    __int128_t time = get_current_timestamp();

    if (sentry->inode->type == HYDROGEN_DIRECTORY) {
        srcdir->links -= 1;
        dstdir->links += 1;
    }

    if (dentry->inode) {
        if (dentry->inode->type == HYDROGEN_DIRECTORY) {
            dentry->inode->links = 0;
            dstdir->links -= 1;
        } else {
            dentry->inode->links -= 1;
        }

        dentry->inode->ctime = time;
        inode_deref(dentry->inode);
        dentry->inode = NULL;

        dentry_deref(dentry);
    }

    srcdir->ctime = time;
    srcdir->mtime = time;

    dstdir->ctime = time;
    dstdir->mtime = time;

    return 0;
}

static const inode_ops_t ramfs_inode_directory_ops = {
        .free = ramfs_inode_free,
        .chmodown = ramfs_inode_chmodown,
        .utime = ramfs_inode_utime,
        .directory.open = ramfs_inode_directory_open,
        .directory.lookup = ramfs_inode_directory_lookup,
        .directory.create = ramfs_inode_directory_create,
        .directory.symlink = ramfs_inode_directory_symlink,
        .directory.link = ramfs_inode_directory_link,
        .directory.unlink = ramfs_inode_directory_unlink,
        .directory.rename = ramfs_inode_directory_rename,
};

int ramfs_create(filesystem_t **out, uint32_t root_mode) {
    ramfs_fs_t *fs = vmalloc(sizeof(*fs));
    if (unlikely(!fs)) return ENOMEM;
    memset(fs, 0, sizeof(*fs));
    fs->base.block_size = PAGE_SIZE;

    ident_t *ident = ident_get(current_thread->process);
    inode_t *root;
    int error = create_ramfs_inode(fs, NULL, &root, HYDROGEN_DIRECTORY, ident, root_mode, NULL);
    ident_deref(ident);
    if (unlikely(error)) {
        vfree(fs, sizeof(*fs));
        return error;
    }

    error = create_root_dentry(&fs->base, root);
    if (unlikely(error)) {
        inode_deref(root);
        vfree(fs, sizeof(*fs));
        return error;
    }

    fs->base.id = get_next_fs_id();
    *out = &fs->base;
    return 0;
}
