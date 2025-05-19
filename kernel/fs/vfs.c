#include "fs/vfs.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "hydrogen/fcntl.h"
#include "hydrogen/filesystem.h"
#include "hydrogen/limits.h"
#include "hydrogen/types.h"
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "string.h"
#include "util/hash.h"
#include "util/hlist.h"
#include "util/list.h"
#include "util/object.h"
#include "util/refcount.h"
#include "util/time.h"
#include <stddef.h>
#include <stdint.h>

static dentry_t root_dentry = {.references = 1};

static void vfs_init(void) {
    root_dentry.references += 2;
    rcu_write(current_thread->process->work_dir, &root_dentry);
    rcu_write(current_thread->process->root_dir, &root_dentry);
}

INIT_DEFINE(vfs, vfs_init);

int access_inode(inode_t *inode, ident_t *ident, uint32_t type, bool use_real) {
    if (ident->euid == 0) {
        if ((type & HYDROGEN_FILE_EXEC) != 0 && (inode->mode & (__S_IXUSR | __S_IXGRP | __S_IXOTH)) == 0) {
            return EACCES;
        }

        return 0;
    }

    uint32_t mask = 0;

    if (type & HYDROGEN_FILE_READ) mask |= __S_IROTH;
    if (type & HYDROGEN_FILE_WRITE) mask |= __S_IWOTH;
    if (type & HYDROGEN_FILE_EXEC) mask |= __S_IXOTH;

    relation_t relation = get_relation(ident, inode->uid, inode->gid, use_real);

    switch (relation) {
    case RELATION_OTHER: break;
    case RELATION_GROUP: mask <<= 3; break;
    case RELATION_OWNER: mask <<= 6; break;
    default: UNREACHABLE();
    }

    return (inode->mode & mask) == mask ? 0 : EACCES;
}

#define LOOKUP_FOLLOW_SYMLINKS (1u << 8)
#define LOOKUP_MUST_EXIST (1u << 9)
#define LOOKUP_MUST_NOT_EXIST (1u << 10)
#define LOOKUP_ALLOW_TRAILING (1u << 11)
#define LOOKUP_WRITABLE_FS (1u << 12)
#define LOOKUP_NO_TRAILING_DOT (1u << 13)
#define LOOKUP_REAL_ID (1u << 14)

static int lookup(dentry_t **entry, const char *path, size_t length, ident_t *ident, uint32_t flags);

static void mount_top(dentry_t **entry) {
    dentry_t *current = *entry;

    for (;;) {
        filesystem_t *mounted = current->mounted;
        if (!mounted) break;
        dentry_ref(mounted->root);
        mutex_rel(&current->lock);
        dentry_deref(current);
        current = mounted->root;
        mutex_acq(&current->lock, 0, false);
    }

    *entry = current;
}

// *entry must be locked. it is dereferenced - even on error. on success, it is set to the new dentry.
static int follow_symlinks(dentry_t **entry, ident_t *ident, uint32_t flags) {
    dentry_t *current = *entry;

    while (current->inode != NULL && current->inode->type == HYDROGEN_SYMLINK) {
        inode_t *inode = current->inode;
        inode_ref(inode);
        mutex_rel(&current->lock);

        dentry_t *parent = current->parent;
        dentry_ref(parent);
        dentry_deref(current);

        int error;
        mutex_acq(&inode->lock, 0, false);

        if (inode->size != 0 && inode->symlink == NULL) {
            error = inode->ops->symlink.readlink(inode);
        } else {
            error = 0;
        }

        mutex_rel(&inode->lock);

        if (likely(error == 0)) {
            current = parent;
            error = lookup(&current, inode->symlink, inode->size, ident, flags);
        }

        inode_deref(inode);
        dentry_deref(parent);
        if (unlikely(error)) return error;
    }

    *entry = current;
    return 0;
}

static int maybe_expand(dentry_t *dir) {
    if (dir->count < dir->capacity - (dir->capacity / 4)) return 0;

    size_t new_cap = dir->capacity ? dir->capacity * 2 : 8;
    size_t new_siz = new_cap * sizeof(*dir->children);
    hlist_t *new_tbl = vmalloc(new_siz);
    if (unlikely(!new_tbl)) return ENOMEM;
    memset(new_tbl, 0, new_siz);

    for (size_t i = 0; i < dir->capacity; i++) {
        for (;;) {
            dentry_t *entry = HLIST_REMOVE_HEAD(dir->children[i], dentry_t, node);
            if (!entry) break;
            hlist_insert_head(&new_tbl[entry->name.hash & (new_cap - 1)], &entry->node);
        }
    }

    vfree(dir->children, dir->capacity * sizeof(*dir->children));
    dir->children = new_tbl;
    dir->capacity = new_cap;
    return 0;
}

static int single_lookup(dentry_t **entry, const char *name, size_t length, ident_t *ident) {
    dentry_t *parent = *entry;
    uint64_t hash = make_hash_blob(name, length);

    if (parent->capacity > 0) {
        dentry_t *current = HLIST_HEAD(parent->children[hash & (parent->capacity - 1)], dentry_t, node);

        while (current != NULL) {
            if (current->name.hash == hash && current->name.size == length &&
                memcmp(current->name.data, name, length) == 0) {
                *entry = current;
                dentry_ref(current);
                return 0;
            }

            current = HLIST_NEXT(*current, dentry_t, node);
        }
    }

    int error = maybe_expand(parent);
    if (unlikely(error)) return error;

    dentry_t *child = vmalloc(sizeof(*child));
    if (unlikely(!child)) return ENOMEM;

    memset(child, 0, sizeof(*child));
    child->references = 1;
    child->fs = parent->fs;
    child->parent = parent;
    child->name.data = vmalloc(length);
    if (unlikely(!child->name.data)) {
        vfree(child, sizeof(*child));
        return ENOMEM;
    }
    memcpy(child->name.data, name, length);
    child->name.size = length;
    child->name.hash = hash;
    child->present = true;

    error = parent->inode->ops->directory.lookup(parent->inode, child);
    if (error != 0 && unlikely(error != ENOENT)) {
        vfree(child->name.data, length);
        vfree(child, sizeof(*child));
        return error;
    }

    dentry_ref(parent);
    hlist_insert_head(&parent->children[hash & (parent->capacity - 1)], &child->node);
    list_insert_tail(&parent->child_list, &child->list_node);

    parent->count += 1;
    if (error == 0) parent->real_count += 1;

    *entry = child;
    return 0;
}

static int lookup(dentry_t **entry, const char *path, size_t length, ident_t *ident, uint32_t flags) {
    if ((flags & 0xff) >= __SYMLOOP_MAX) return ELOOP;

    dentry_t *current = *entry;

    rcu_state_t state = rcu_read_lock();

    dentry_t *root = rcu_read(current_thread->process->root_dir);
    dentry_ref(root);

    if (length > 0 && path[0] == '/') {
        current = root;
        dentry_ref(current);
        rcu_read_unlock(state);
        mutex_acq(&current->lock, 0, false);
        mount_top(&current);
        path += 1;
        length -= 1;
    } else {
        if (current == NULL) current = rcu_read(current_thread->process->work_dir);
        dentry_ref(current);
        rcu_read_unlock(state);
        mutex_acq(&current->lock, 0, false);
    }

    int error;
    bool was_dot = false;

    while (length != 0) {
        while (length > 0 && path[0] == '/') {
            path++;
            length--;
        }

        size_t comp_len = 0;
        while (comp_len < length && path[comp_len] != '/') comp_len++;

        uint32_t sym_flags = ((flags & (0xff | LOOKUP_REAL_ID)) + 1) | LOOKUP_ALLOW_TRAILING;

        if (comp_len == 0) {
            sym_flags |= flags & LOOKUP_NO_TRAILING_DOT;
        }

        error = follow_symlinks(&current, ident, sym_flags);
        if (unlikely(error)) goto err;

        if (unlikely(!current->inode)) {
            if ((flags & LOOKUP_ALLOW_TRAILING) != 0 && comp_len == 0) break;
            error = ENOENT;
            goto err;
        }

        if (unlikely(current->inode->type != HYDROGEN_DIRECTORY)) {
            error = ENOTDIR;
            goto err;
        }

        mutex_acq(&current->inode->lock, 0, false);

        error = access_inode(current->inode, ident, HYDROGEN_FILE_EXEC, flags & LOOKUP_REAL_ID);
        if (unlikely(error)) goto err2;

        if (comp_len == 1 && path[0] == '.') {
            was_dot = true;
            mutex_rel(&current->inode->lock);
        } else if (comp_len == 2 && path[0] == '.' && path[1] == '.') {
            was_dot = true;
            mutex_rel(&current->inode->lock);

            for (dentry_t *entry = current; entry != root; entry = entry->fs->mountpoint) {
                dentry_t *parent = entry->parent;

                if (parent != NULL) {
                    dentry_ref(parent);
                    mutex_rel(&current->lock);
                    dentry_deref(current);
                    current = parent;
                    mutex_acq(&parent->lock, 0, false);
                    break;
                }
            }
        } else if (comp_len == 0) {
            // don't modify was_dot here
            mutex_rel(&current->inode->lock);
        } else {
            was_dot = false;

            dentry_t *child = current;
            error = single_lookup(&child, path, comp_len, ident);
            if (unlikely(error)) goto err2;
            mutex_rel(&current->inode->lock);
            mutex_rel(&current->lock);
            dentry_deref(current);
            current = child;
            mutex_acq(&current->lock, 0, false);
            mount_top(&current);
        }

        path += comp_len;
        length -= comp_len;
    }

    if ((flags & LOOKUP_NO_TRAILING_DOT) != 0 && unlikely(was_dot)) {
        error = EINVAL;
        goto err;
    }

    if (flags & LOOKUP_FOLLOW_SYMLINKS) {
        error = follow_symlinks(&current, ident, (flags & (0xff | LOOKUP_ALLOW_TRAILING | LOOKUP_NO_TRAILING_DOT)) + 1);
        if (unlikely(error)) goto err;
    }

    if ((flags & LOOKUP_MUST_EXIST) != 0 && current->inode == NULL) {
        error = ENOENT;
        goto err;
    }

    if ((flags & LOOKUP_MUST_NOT_EXIST) != 0 && current->inode != NULL) {
        error = EEXIST;
        goto err;
    }

    if ((flags & LOOKUP_WRITABLE_FS) != 0 && (current->fs->flags & FILESYSTEM_READ_ONLY) != 0) {
        error = EROFS;
        goto err;
    }

    *entry = current;
    dentry_deref(root);
    return 0;
err2:
    mutex_rel(&current->inode->lock);
err:
    mutex_rel(&current->lock);
    dentry_deref(current);
    dentry_deref(root);
    return error;
}

static int flookup(dentry_t **entry, file_t *file, const void *path, size_t length, ident_t *ident, uint32_t flags) {
    *entry = file ? file->path : NULL;
    return lookup(entry, path, length, ident, flags);
}

int vfs_mount(file_t *file, const void *path, size_t length, filesystem_t *fs) {
    ident_t *ident = ident_get(current_thread->process);
    int error;

    if (unlikely(ident->euid != 0)) {
        error = EPERM;
        goto ret;
    }

    dentry_t *entry;
    error = flookup(&entry, file, path, length, ident, 0);
    if (unlikely(error)) goto ret;

    if (entry != &root_dentry) {
        if (unlikely(entry->inode == NULL)) {
            error = ENOENT;
            goto ret2;
        }

        if (unlikely(entry->inode->type != HYDROGEN_DIRECTORY)) {
            error = ENOTDIR;
            goto ret2;
        }
    }

    if (unlikely(entry->mounted)) {
        error = EBUSY;
        goto ret2;
    }

    entry->mounted = fs;
    fs->mountpoint = entry;
    dentry_ref(entry);

ret2:
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_chdir(struct process *process, file_t *file, const void *path, size_t length) {
    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, file, path, length, ident, LOOKUP_FOLLOW_SYMLINKS | LOOKUP_MUST_EXIST);
    ident_deref(ident);
    if (unlikely(error)) return error;

    bool ok = entry->inode->type == HYDROGEN_DIRECTORY;
    mutex_rel(&entry->lock);
    if (unlikely(!ok)) {
        dentry_deref(entry);
        return ENOTDIR;
    }

    entry = __atomic_exchange_n(&process->work_dir, entry, __ATOMIC_ACQ_REL);
    rcu_sync();
    dentry_deref(entry);

    return 0;
}

int vfs_chroot(struct process *process, file_t *file, const void *path, size_t length) {
    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, file, path, length, ident, LOOKUP_FOLLOW_SYMLINKS | LOOKUP_MUST_EXIST);
    ident_deref(ident);
    if (unlikely(error)) return error;

    bool ok = entry->inode->type == HYDROGEN_DIRECTORY;
    mutex_rel(&entry->lock);
    if (unlikely(!ok)) {
        dentry_deref(entry);
        return ENOTDIR;
    }

    // this must be done before switching the root dir, as otherwise the work dir might be inaccessible from the root
    dentry_t *old_work = __atomic_exchange_n(&process->work_dir, entry, __ATOMIC_ACQ_REL);
    entry = __atomic_exchange_n(&process->root_dir, entry, __ATOMIC_ACQ_REL);
    rcu_sync();
    dentry_deref(entry);
    dentry_deref(old_work);

    return 0;
}

uint32_t vfs_umask(process_t *process, uint32_t mask) {
    return __atomic_exchange_n(&process->umask, mask & FILE_PERM_BITS, __ATOMIC_ACQ_REL);
}

static void use_umask(uint32_t *mode) {
    *mode &= ~__atomic_load_n(&current_thread->process->umask, __ATOMIC_ACQUIRE);
}

int vfs_create(file_t *rel, const void *path, size_t length, hydrogen_file_type_t type, uint32_t mode) {
    if (unlikely(type != HYDROGEN_REGULAR_FILE && type != HYDROGEN_DIRECTORY)) return EINVAL;
    if (unlikely((mode & ~FILE_MAKE_BITS) != 0)) return EINVAL;
    use_umask(&mode);

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(
            &entry,
            rel,
            path,
            length,
            ident,
            LOOKUP_ALLOW_TRAILING | LOOKUP_MUST_NOT_EXIST | LOOKUP_WRITABLE_FS
    );
    if (unlikely(error)) goto ret;

    dentry_t *parent = entry->parent;
    mutex_acq(&parent->lock, 0, false);

    if (unlikely(parent->inode == NULL)) {
        error = ENOENT;
        goto ret2;
    }

    mutex_acq(&parent->inode->lock, 0, false);

    error = access_inode(parent->inode, ident, HYDROGEN_FILE_WRITE, false);
    if (unlikely(error)) goto ret3;

    error = parent->inode->ops->directory.create(parent->inode, entry, type, ident, mode);
    if (unlikely(error)) goto ret3;

    parent->real_count += 1;
ret3:
    mutex_rel(&parent->inode->lock);
ret2:
    mutex_rel(&parent->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_symlink(file_t *rel, const void *path, size_t length, const void *tpath, size_t tlength) {
    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(
            &entry,
            rel,
            path,
            length,
            ident,
            LOOKUP_ALLOW_TRAILING | LOOKUP_MUST_NOT_EXIST | LOOKUP_WRITABLE_FS
    );
    if (unlikely(error)) goto ret;

    dentry_t *parent = entry->parent;
    mutex_acq(&parent->lock, 0, false);

    if (unlikely(parent->inode == NULL)) {
        error = ENOENT;
        goto ret2;
    }

    mutex_acq(&parent->inode->lock, 0, false);

    error = access_inode(parent->inode, ident, HYDROGEN_FILE_WRITE, false);
    if (unlikely(error)) goto ret3;

    error = parent->inode->ops->directory.symlink(parent->inode, entry, tpath, tlength, ident);
    if (unlikely(error)) goto ret3;

    parent->real_count += 1;
ret3:
    mutex_rel(&parent->inode->lock);
ret2:
    mutex_rel(&parent->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_link(file_t *rel, const void *path, size_t length, file_t *trel, const void *tpath, size_t tlength, int flags) {
    if (unlikely((flags & ~__AT_SYMLINK_FOLLOW) != 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS;
    if (flags & __AT_SYMLINK_FOLLOW) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *source, *target;
    int error;

    for (;;) {
        error = flookup(&target, trel, tpath, tlength, ident, lookup_flags);
        if (unlikely(error)) goto ret;

        bool ok = target->inode->type == HYDROGEN_DIRECTORY;
        mutex_rel(&target->lock);
        if (unlikely(!ok)) {
            error = EPERM;
            goto ret2;
        }

        error = flookup(&source, rel, path, length, ident, LOOKUP_MUST_NOT_EXIST | LOOKUP_WRITABLE_FS);
        if (unlikely(error)) goto ret2;

        if (unlikely(source->fs != target->fs)) {
            error = EXDEV;
            goto ret3;
        }

        if ((uintptr_t)source < (uintptr_t)target) {
            mutex_acq(&target->lock, 0, false);
        } else {
            mutex_rel(&source->lock);
            mutex_acq(&target->lock, 0, false);
            mutex_acq(&source->lock, 0, false);
        }

        if (source->present && target->present) break;

        mutex_rel(&source->lock);
        mutex_rel(&target->lock);
        dentry_deref(source);
        dentry_deref(target);
    }

    if (unlikely(source->inode != NULL)) {
        error = EEXIST;
        goto ret4;
    }

    inode_t *tnode = target->inode;

    if (unlikely(tnode == NULL)) {
        error = ENOENT;
        goto ret4;
    }

    dentry_t *sparent = source->parent;
    mutex_acq(&sparent->lock, 0, false);

    inode_t *spnode = source->parent->inode;

    if (unlikely(spnode == NULL)) {
        error = ENOENT;
        goto ret5;
    }

    if ((uintptr_t)spnode < (uintptr_t)tnode) {
        mutex_acq(&spnode->lock, 0, false);
        mutex_acq(&tnode->lock, 0, false);
    } else {
        mutex_acq(&tnode->lock, 0, false);
        mutex_acq(&spnode->lock, 0, false);
    }

    error = access_inode(spnode, ident, HYDROGEN_FILE_WRITE, false);
    if (unlikely(error)) goto ret6;

    error = spnode->ops->directory.link(spnode, source, tnode);
    if (unlikely(error)) goto ret6;

    source->parent->real_count += 1;
ret6:
    mutex_rel(&spnode->lock);
    mutex_rel(&tnode->lock);
ret5:
    mutex_rel(&sparent->lock);
ret4:
    mutex_rel(&target->lock);
ret3:
    mutex_rel(&source->lock);
    dentry_deref(source);
ret2:
    dentry_deref(target);
ret:
    ident_deref(ident);
    return error;
}

static int access_sticky(inode_t *dir, inode_t *inode, ident_t *ident) {
    if (dir->mode & __S_ISVTX) {
        if (!ident->euid) return 0;
        if (ident->euid == dir->uid) return 0;
        if (ident->euid == inode->uid) return 0;

        return EACCES;
    }

    return access_inode(dir, ident, HYDROGEN_FILE_WRITE, false);
}

static void remove_from_parent(dentry_t *entry) {
    hlist_remove(&entry->parent->children[entry->name.hash & (entry->parent->capacity - 1)], &entry->node);
    entry->parent->count -= 1;
    if (entry->inode) entry->parent->real_count -= 1;

    list_remove(&entry->parent->child_list, &entry->list_node);
}

int vfs_unlink(file_t *rel, const void *path, size_t length, int flags) {
    if (unlikely((flags & ~__AT_REMOVEDIR) != 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS;

    if (flags & __AT_REMOVEDIR) lookup_flags |= LOOKUP_NO_TRAILING_DOT;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) goto ret;

    if (flags & __AT_REMOVEDIR) {
        if (entry->inode->type != HYDROGEN_DIRECTORY) {
            error = ENOTDIR;
            goto ret2;
        }

        if (entry->parent == NULL || entry->mounted != NULL) {
            error = EBUSY;
            goto ret2;
        }

        if (entry->real_count != 0) {
            error = ENOTEMPTY;
            goto ret2;
        }
    } else if (entry->inode->type == HYDROGEN_DIRECTORY) {
        error = EISDIR;
        goto ret2;
    }

    mutex_acq(&entry->inode->lock, 0, false);

    inode_t *parent = entry->parent->inode;
    mutex_acq(&entry->parent->lock, 0, false);
    mutex_acq(&parent->lock, 0, false);

    error = access_sticky(parent, entry->inode, ident);
    if (unlikely(error)) goto ret3;

    error = parent->ops->directory.unlink(parent, entry);
    if (unlikely(error)) goto ret3;

    remove_from_parent(entry);
    entry->present = false;

ret3:
    mutex_rel(&parent->lock);
    mutex_rel(&entry->parent->lock);
    mutex_rel(&entry->inode->lock);
ret2:
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return 0;
}

// returns true if a is an ancestor of b. does not work across mount boundaries.
static bool is_ancestor(dentry_t *a, dentry_t *b) {
    do {
        if (b == a) return true;
        b = b->parent;
    } while (b != NULL);

    return false;
}

int vfs_rename(file_t *rel, const void *path, size_t length, file_t *trel, const void *tpath, size_t tlength) {
    ident_t *ident = ident_get(current_thread->process);
    dentry_t *source, *target;
    int error;

    for (;;) {
        error = flookup(
                &source,
                rel,
                path,
                length,
                ident,
                LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS | LOOKUP_NO_TRAILING_DOT
        );
        if (unlikely(error)) goto ret;

        bool dir = source->inode->type == HYDROGEN_DIRECTORY;
        mutex_rel(&source->lock);

        uint32_t lookup_flags = LOOKUP_WRITABLE_FS | LOOKUP_NO_TRAILING_DOT;
        if (dir) lookup_flags |= LOOKUP_ALLOW_TRAILING;

        error = flookup(&target, trel, tpath, tlength, ident, lookup_flags);
        if (unlikely(error)) goto ret2;

        if (source == target) goto ret3; // success, no other action

        if (unlikely(source->fs != target->fs)) {
            error = EXDEV;
            goto ret3;
        }

        if ((uintptr_t)source < (uintptr_t)target) {
            mutex_acq(&source->lock, 0, false);
        } else {
            mutex_rel(&target->lock);
            mutex_acq(&source->lock, 0, false);
            mutex_acq(&target->lock, 0, false);
        }

        if (source->present && target->present) break;

        mutex_rel(&source->lock);
        mutex_rel(&target->lock);
        dentry_deref(source);
        dentry_deref(target);
    }

    if (unlikely(!source->inode)) {
        error = ENOENT;
        goto ret4;
    }

    if (unlikely(source->inode == target->inode)) goto ret4; // success, no other action

    if (unlikely(is_ancestor(source, target))) {
        error = EINVAL;
        goto ret4;
    }

    dentry_t *sparent = source->parent;
    dentry_t *tparent = target->parent;

    if (unlikely(!sparent) || unlikely(!tparent) || unlikely(target->mounted)) {
        error = EBUSY;
        goto ret4;
    }

    if ((uintptr_t)sparent < (uintptr_t)tparent) {
        mutex_acq(&sparent->lock, 0, false);
        mutex_acq(&tparent->lock, 0, false);
    } else {
        mutex_acq(&tparent->lock, 0, false);
        mutex_acq(&sparent->lock, 0, false);
    }

    inode_t *spnode = sparent->inode;
    inode_t *tpnode = tparent->inode;

    if (unlikely(!tpnode)) {
        error = ENOENT;
        goto ret5;
    }

    if ((uintptr_t)spnode < (uintptr_t)tpnode) {
        mutex_acq(&spnode->lock, 0, false);
        mutex_acq(&tpnode->lock, 0, false);
    } else {
        mutex_acq(&tpnode->lock, 0, false);
        mutex_acq(&spnode->lock, 0, false);
    }

    inode_t *snode = source->inode;
    inode_t *tnode = target->inode;

    if ((uintptr_t)snode < (uintptr_t)tnode) {
        mutex_acq(&snode->lock, 0, false);
        mutex_acq(&tnode->lock, 0, false);
    } else {
        mutex_acq(&tnode->lock, 0, false);
        mutex_acq(&snode->lock, 0, false);
    }

    error = access_sticky(spnode, snode, ident);
    if (unlikely(error)) goto ret6;

    if (tnode) {
        error = access_sticky(tpnode, tnode, ident);
        if (unlikely(error)) goto ret6;

        if (tnode->type == HYDROGEN_DIRECTORY) {
            if (unlikely(snode->type != HYDROGEN_DIRECTORY)) {
                error = EISDIR;
                goto ret6;
            }

            if (unlikely(target->real_count != 0)) {
                error = ENOTEMPTY;
                goto ret6;
            }
        } else if (unlikely(snode->type == HYDROGEN_DIRECTORY)) {
            error = ENOTDIR;
            goto ret6;
        }
    } else {
        error = access_inode(tpnode, ident, HYDROGEN_FILE_WRITE, false);
        if (unlikely(error)) goto ret6;
    }

    dname_t new_name = target->name;
    new_name.data = vmalloc(new_name.size);
    if (unlikely(!new_name.data)) {
        error = ENOMEM;
        goto ret6;
    }
    memcpy(new_name.data, target->name.data, new_name.size);

    error = spnode->ops->directory.rename(spnode, source, tpnode, target);
    if (unlikely(error)) goto ret6;

    remove_from_parent(source);
    remove_from_parent(target);
    target->present = false;

    vfree(source->name.data, source->name.size);
    source->parent = tparent;
    source->name = new_name;
    dentry_ref(tparent);
    dentry_deref(sparent);

    hlist_insert_head(&tparent->children[source->name.hash & (tparent->capacity - 1)], &source->node);
    tparent->count += 1;
    tparent->real_count += 1;
    list_insert_tail(&tparent->child_list, &source->list_node);

ret6:
    mutex_rel(&snode->lock);
    mutex_rel(&tnode->lock);
    mutex_rel(&spnode->lock);
    mutex_rel(&tpnode->lock);
ret5:
    mutex_rel(&sparent->lock);
    mutex_rel(&tparent->lock);
ret4:
    mutex_rel(&source->lock);
ret3:
    mutex_rel(&target->lock);
    dentry_deref(target);
ret2:
    dentry_deref(source);
ret:
    ident_deref(ident);
    return error;
}

int vfs_access(file_t *rel, const void *path, size_t length, uint32_t type, int flags) {
    if (unlikely((type & ~(HYDROGEN_FILE_READ | HYDROGEN_FILE_WRITE | HYDROGEN_FILE_EXEC)) != 0)) return EINVAL;
    if (unlikely((flags & ~__AT_EACCESS) != 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_FOLLOW_SYMLINKS | LOOKUP_MUST_EXIST;

    if ((flags & __AT_EACCESS) == 0) lookup_flags |= LOOKUP_REAL_ID;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) goto ret;

    mutex_acq(&entry->inode->lock, 0, false);
    error = access_inode(entry->inode, ident, type, (flags & __AT_EACCESS) == 0);
    mutex_rel(&entry->inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_stat(file_t *rel, const void *path, size_t length, hydrogen_file_information_t *out, int flags) {
    if (unlikely((flags & ~__AT_SYMLINK_NOFOLLOW) == 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST;

    if ((flags & __AT_SYMLINK_NOFOLLOW) == 0) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    ident_deref(ident);
    if (unlikely(error)) return error;

    hydrogen_file_information_t info = {};
    inode_t *inode = entry->inode;
    mutex_acq(&inode->lock, 0, false);

    info.filesystem_id = inode->fs->id;
    info.id = inode->id;
    info.links = inode->links;
    info.blocks = inode->blocks;
    info.size = inode->size;
    info.block_size = inode->fs->block_size;
    info.atime = inode->atime;
    info.btime = inode->btime;
    info.ctime = inode->ctime;
    info.mtime = inode->mtime;
    info.type = inode->type;
    info.mode = inode->mode;
    info.uid = inode->uid;
    info.gid = inode->gid;

    mutex_rel(&inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);

    return user_memcpy(out, &info, sizeof(*out));
}

hydrogen_ret_t vfs_readlink(file_t *rel, const void *path, size_t length, void *buffer, size_t size) {
    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, LOOKUP_MUST_EXIST);
    ident_deref(ident);
    if (unlikely(error)) return ret_error(error);

    inode_t *inode = entry->inode;
    if (inode->type != HYDROGEN_SYMLINK) goto ret;

    mutex_acq(&inode->lock, 0, false);
    if (!inode->symlink && inode->size) error = inode->ops->symlink.readlink(inode);
    mutex_rel(&inode->lock);
    if (unlikely(error)) goto ret;

    size_t full_size = inode->size;
    error = user_memcpy(buffer, inode->symlink, size < full_size ? size : full_size);
ret:
    mutex_rel(&entry->lock);
    dentry_deref(entry);
    return RET_MAYBE(integer, error, full_size);
}

int vfs_chmod(file_t *rel, const void *path, size_t length, uint32_t mode, int flags) {
    if (unlikely((mode & ~FILE_MODE_BITS) != 0)) return EINVAL;
    if (unlikely((flags & ~__AT_SYMLINK_NOFOLLOW) != 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS;

    if ((flags & __AT_SYMLINK_NOFOLLOW) == 0) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) goto ret;

    inode_t *inode = entry->inode;
    mutex_acq(&inode->lock, 0, false);

    if (ident->euid != 0) {
        if (unlikely(ident->euid != inode->uid)) {
            error = EPERM;
            goto ret2;
        }

        if (get_relation(ident, -1, inode->gid, false) != RELATION_GROUP) {
            mode &= ~__S_ISGID;
        }
    }

    error = inode->ops->chmodown(inode, mode, inode->uid, inode->gid);
ret2:
    mutex_rel(&inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_chown(file_t *rel, const void *path, size_t length, uint32_t uid, uint32_t gid, int flags) {
    if (unlikely((flags & ~__AT_SYMLINK_NOFOLLOW) != 0)) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS;

    if ((flags & __AT_SYMLINK_NOFOLLOW) == 0) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) goto ret;

    inode_t *inode = entry->inode;
    mutex_acq(&inode->lock, 0, false);

    if (uid == (uint32_t)-1) uid = inode->uid;
    if (gid == (uint32_t)-1) gid = inode->gid;

    uint32_t mode = inode->mode;

    if (ident->euid != 0) {
        if (unlikely(ident->euid != uid)) {
            error = EPERM;
            goto ret2;
        }

        if (get_relation(ident, -1, inode->gid, false) != RELATION_GROUP) {
            error = EPERM;
            goto ret2;
        }

        if ((mode & (__S_IXUSR | __S_IXGRP | __S_IXOTH)) != 0) {
            mode &= ~(__S_ISGID | __S_ISUID);
        }
    }

    error = inode->ops->chmodown(inode, mode, uid, gid);
ret2:
    mutex_rel(&inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

static int do_access(file_t *rel, inode_t *inode, ident_t *ident, size_t path_len, uint32_t type) {
    if (path_len == 0) {
        if ((type & HYDROGEN_FILE_READ) != 0 && unlikely((rel->flags & __O_RDONLY) == 0)) return EACCES;
        if ((type & HYDROGEN_FILE_WRITE) != 0 && unlikely((rel->flags & __O_WRONLY) == 0)) return EACCES;
        return 0;
    }

    return access_inode(inode, ident, type, false);
}

int vfs_utime(
        file_t *rel,
        const void *path,
        size_t length,
        __int128_t atime,
        __int128_t ctime,
        __int128_t mtime,
        int flags
) {
    if (unlikely((flags & ~__AT_SYMLINK_NOFOLLOW)) == 0) return EINVAL;

    uint32_t lookup_flags = LOOKUP_MUST_EXIST | LOOKUP_WRITABLE_FS;

    if ((flags & __AT_SYMLINK_NOFOLLOW) == 0) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) goto ret;

    inode_t *inode = entry->inode;
    mutex_acq(&inode->lock, 0, false);

    if (ident->euid != 0) {
        if (ident->euid != inode->uid) {
            if ((atime != HYDROGEN_FILE_TIME_OMIT && atime != HYDROGEN_FILE_TIME_NOW) ||
                (ctime != HYDROGEN_FILE_TIME_OMIT && ctime != HYDROGEN_FILE_TIME_NOW) ||
                (mtime != HYDROGEN_FILE_TIME_OMIT && mtime != HYDROGEN_FILE_TIME_NOW)) {
                error = EACCES;
                goto ret2;
            }

            error = do_access(rel, inode, ident, length, HYDROGEN_FILE_WRITE);
            if (unlikely(error)) goto ret2;
        }
    }

    error = inode->ops->utime(inode, atime, ctime, mtime);
ret2:
    mutex_rel(&inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

int vfs_truncate(file_t *rel, const void *path, size_t length, uint64_t size) {
    if (unlikely(size > INT64_MAX)) return EINVAL;

    ident_t *ident = ident_get(current_thread->process);
    dentry_t *entry;
    int error = flookup(
            &entry,
            rel,
            path,
            length,
            ident,
            LOOKUP_MUST_EXIST | LOOKUP_FOLLOW_SYMLINKS | LOOKUP_WRITABLE_FS
    );
    if (unlikely(error)) goto ret;

    inode_t *inode = entry->inode;
    mutex_acq(&inode->lock, 0, false);

    if (unlikely(inode->type != HYDROGEN_REGULAR_FILE)) {
        error = EINVAL;
        goto ret2;
    }

    error = do_access(rel, inode, ident, length, HYDROGEN_FILE_WRITE);
    if (unlikely(error)) goto ret2;

    error = inode->ops->regular.truncate(inode, size);
ret2:
    mutex_rel(&inode->lock);
    mutex_rel(&entry->lock);
    dentry_deref(entry);
ret:
    ident_deref(ident);
    return error;
}

static void regular_file_free(object_t *ptr) {
    file_t *self = (file_t *)ptr;
    dentry_deref(self->path);
    inode_deref(self->inode);
    vfree(self, sizeof(*self));
}

static hydrogen_ret_t regular_file_seek(file_t *self, hydrogen_seek_anchor_t anchor, int64_t offset) {
    uint64_t position;

    switch (anchor) {
    case HYDROGEN_SEEK_BEGIN: position = 0; break;
    case HYDROGEN_SEEK_CURRENT: position = self->position; break;
    case HYDROGEN_SEEK_END:
        mutex_acq(&self->inode->lock, 0, false);
        position = self->inode->size;
        mutex_rel(&self->inode->lock);
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

static hydrogen_ret_t regular_file_read(file_t *self, void *buffer, size_t size, uint64_t position) {
    mutex_acq(&self->inode->lock, 0, false);

    if (position >= self->inode->size) {
        mutex_rel(&self->inode->lock);
        return ret_integer(0);
    }

    int error = self->inode->ops
                        ->utime(self->inode, HYDROGEN_FILE_TIME_NOW, HYDROGEN_FILE_TIME_OMIT, HYDROGEN_FILE_TIME_OMIT);
    if (unlikely(error)) {
        mutex_rel(&self->inode->lock);
        return ret_error(error);
    }

    uint64_t available = self->inode->size - position;
    size_t count = available < size ? available : size;

    error = mem_object_read(self->inode->regular, buffer, count, position);
    mutex_rel(&self->inode->lock);
    return RET_MAYBE(integer, error, count);
}

static hydrogen_ret_t regular_file_write(file_t *self, const void *buffer, size_t size, uint64_t position, bool rpos) {
    mutex_acq(&self->inode->lock, 0, false);

    if (!rpos && (self->flags & __O_APPEND) != 0) position = self->inode->size;

    uint64_t wanted_size = position + size;
    if (wanted_size < position || wanted_size > INT64_MAX) wanted_size = INT64_MAX;

    if (wanted_size <= position) {
        mutex_rel(&self->inode->lock);
        return ret_error(EFBIG);
    }

    int error;

    if (wanted_size > self->inode->size) {
        error = self->inode->ops->regular.truncate(self->inode, wanted_size);
    } else {
        error = self->inode->ops
                        ->utime(self->inode, HYDROGEN_FILE_TIME_OMIT, HYDROGEN_FILE_TIME_NOW, HYDROGEN_FILE_TIME_NOW);
    }

    if (unlikely(error)) {
        mutex_rel(&self->inode->lock);
        return ret_error(error);
    }

    uint64_t available = self->inode->size - position;
    size_t count = available < size ? available : size;

    error = mem_object_write(self->inode->regular, buffer, count, position);

    if (likely(error == 0) && !rpos && (self->flags & __O_APPEND) != 0) {
        self->position = self->inode->size - count;
    }

    mutex_rel(&self->inode->lock);
    return RET_MAYBE(integer, error, count);
}

static hydrogen_ret_t regular_file_mmap(
        file_t *self,
        object_rights_t rights,
        vmm_t *vmm,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        uint64_t offset
) {
    return vmm_map(vmm, hint, size, flags, self->inode->regular, rights, offset);
}

static const file_ops_t regular_file_ops = {
        .base.free = regular_file_free,
        .seek = regular_file_seek,
        .read = regular_file_read,
        .write = regular_file_write,
        .mmap = regular_file_mmap,
};

static void open_regular_file(file_t *file, dentry_t *entry, int flags) {
    memset(file, 0, sizeof(*file));
    file->base.ops = &regular_file_ops.base;
    obj_init(&file->base, OBJECT_FILE_DESCRIPTION);
    file->path = entry;
    file->inode = entry->inode;
    file->flags = flags;
    dentry_ref(entry);
    inode_ref(entry->inode);
}

int vfs_open(file_t **out, file_t *rel, const void *path, size_t length, int flags, uint32_t mode, ident_t *ident) {
    if (unlikely((flags & ~FILE_OPEN_FLAGS) != 0)) return EINVAL;
    if (unlikely((mode & ~FILE_PERM_BITS) != 0)) return EINVAL;
    if (unlikely((flags & (__O_CREAT | __O_DIRECTORY)) == (__O_CREAT | __O_DIRECTORY))) return EINVAL;
    use_umask(&mode);

    uint32_t lookup_flags = 0;

    if ((flags & __O_CREAT) == 0) lookup_flags |= LOOKUP_MUST_EXIST;
    if ((flags & __O_EXCL) != 0) lookup_flags |= LOOKUP_MUST_NOT_EXIST;
    if ((flags & (__O_EXCL | __O_NOFOLLOW)) == 0) lookup_flags |= LOOKUP_FOLLOW_SYMLINKS;

    dentry_t *entry;
    int error = flookup(&entry, rel, path, length, ident, lookup_flags);
    if (unlikely(error)) return error;

    file_t *file;

    if (entry->inode == NULL) {
        ASSERT(flags & __O_CREAT);

        file = vmalloc(sizeof(*file));
        if (unlikely(!file)) {
            error = ENOMEM;
            goto ret;
        }

        dentry_t *parent = entry->parent;
        mutex_acq(&parent->lock, 0, false);

        inode_t *inode = parent->inode;

        if (unlikely(!inode)) {
            error = ENOENT;
            mutex_rel(&parent->lock);
            vfree(file, sizeof(*file));
            goto ret;
        }

        mutex_acq(&inode->lock, 0, false);

        error = access_inode(inode, ident, HYDROGEN_FILE_WRITE, false);

        if (unlikely(error)) {
            mutex_rel(&inode->lock);
            mutex_rel(&parent->lock);
            vfree(file, sizeof(*file));
            goto ret;
        }

        error = inode->ops->directory.create(inode, entry, HYDROGEN_REGULAR_FILE, ident, mode);
        mutex_rel(&inode->lock);
        mutex_rel(&parent->lock);
        if (unlikely(error)) {
            vfree(file, sizeof(*file));
            goto ret;
        }
        mutex_acq(&entry->inode->lock, 0, false);
        open_regular_file(file, entry, flags);
        mutex_rel(&entry->inode->lock);
    } else {
        ASSERT((flags & __O_EXCL) == 0);

        mutex_acq(&entry->inode->lock, 0, false);

        if (flags & __O_DIRECTORY) {
            if (entry->inode->type != HYDROGEN_DIRECTORY) {
                mutex_rel(&entry->inode->lock);
                error = ENOTDIR;
                goto ret;
            }

            if (flags & __O_WRONLY) {
                mutex_rel(&entry->inode->lock);
                error = EISDIR;
                goto ret;
            }
        } else if (entry->inode->type == HYDROGEN_DIRECTORY) {
            if (flags & (__O_CREAT | __O_WRONLY)) {
                mutex_rel(&entry->inode->lock);
                error = EISDIR;
                goto ret;
            }
        }

        uint32_t type = 0;

        if (flags & __O_RDONLY) type |= HYDROGEN_FILE_READ;
        if (flags & __O_WRONLY) type |= HYDROGEN_FILE_WRITE;

        error = access_inode(entry->inode, ident, type, false);
        if (unlikely(error)) {
            mutex_rel(&entry->inode->lock);
            goto ret;
        }

        hydrogen_ret_t ret;

        switch (entry->inode->type) {
        case HYDROGEN_DIRECTORY: ret = entry->inode->ops->directory.open(entry->inode, entry, flags); break;
        case HYDROGEN_REGULAR_FILE: {
            if (flags & __O_TRUNC) {
                error = entry->inode->ops->regular.truncate(entry->inode, 0);
                if (unlikely(error)) {
                    ret = ret_error(error);
                    break;
                }
            }

            file_t *file = vmalloc(sizeof(*file));
            if (unlikely(!file)) {
                ret = ret_error(ENOMEM);
                break;
            }
            open_regular_file(file, entry, flags);
            ret = ret_pointer(file);
            break;
        }
        case HYDROGEN_SYMLINK: ret = ret_error(ELOOP); break;
        default: ret = ret_error(ENOTSUP); break;
        }

        mutex_rel(&entry->inode->lock);

        if (unlikely(ret.error)) {
            error = ret.error;
            goto ret;
        }

        file = ret.pointer;
    }

    *out = file;
ret:
    mutex_rel(&entry->lock);
    dentry_deref(entry);
    return error;
}

hydrogen_ret_t vfs_mmap(
        file_t *file,
        object_rights_t rights,
        struct vmm *vmm,
        uintptr_t hint,
        size_t size,
        uint32_t flags,
        uint64_t offset
) {
    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->mmap)) return ret_error(ENODEV);

    return ops->mmap(file, rights, vmm, hint, size, flags, offset);
}

hydrogen_ret_t vfs_pread(file_t *file, void *buffer, size_t size, uint64_t position) {
    if (unlikely(size == 0)) return ret_integer(0);
    if (unlikely(position > INT64_MAX)) return ret_error(EINVAL);
    if (unlikely(file->inode->type == HYDROGEN_DIRECTORY)) return ret_error(EISDIR);

    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->seek)) return ret_error(ESPIPE);
    if (unlikely(!ops->read)) return ret_error(ENXIO);

    return ops->read(file, buffer, size, position);
}

hydrogen_ret_t vfs_pwrite(file_t *file, const void *buffer, size_t size, uint64_t position) {
    if (unlikely(size == 0)) return ret_integer(0);
    if (unlikely(position > INT64_MAX)) return ret_error(EINVAL);

    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->seek)) return ret_error(ESPIPE);
    if (unlikely(!ops->write)) return ret_error(ENXIO);

    return ops->write(file, buffer, size, position, true);
}

hydrogen_ret_t vfs_seek(file_t *file, hydrogen_seek_anchor_t anchor, int64_t offset) {
    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->seek)) return ret_error(ESPIPE);

    mutex_acq(&file->lock, 0, false);
    hydrogen_ret_t ret = ops->seek(file, anchor, offset);
    if (likely(ret.error == 0)) file->position = ret.integer;
    mutex_rel(&file->lock);
    return ret;
}

hydrogen_ret_t vfs_read(file_t *file, void *buffer, size_t size) {
    if (unlikely(size == 0)) return ret_integer(0);
    if (unlikely(file->inode->type == HYDROGEN_DIRECTORY)) return ret_error(EISDIR);

    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->read)) return ret_error(ENXIO);

    mutex_acq(&file->lock, 0, false);
    hydrogen_ret_t ret = ops->read(file, buffer, size, file->position);
    if (likely(ret.error == 0)) file->position += ret.integer;
    mutex_rel(&file->lock);
    return ret;
}

hydrogen_ret_t vfs_readdir(file_t *file, void *buffer, size_t size) {
    if (unlikely(size == 0)) return ret_integer(0);

    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->readdir)) return ret_error(ENOTDIR);

    mutex_acq(&file->lock, 0, false);
    hydrogen_ret_t ret = ops->readdir(file, buffer, size);
    mutex_rel(&file->lock);
    return ret;
}

hydrogen_ret_t vfs_write(file_t *file, const void *buffer, size_t size) {
    if (unlikely(size == 0)) return ret_integer(0);

    const file_ops_t *ops = (const file_ops_t *)file->base.ops;
    if (unlikely(!ops->write)) return ret_error(ENXIO);

    mutex_acq(&file->lock, 0, false);
    hydrogen_ret_t ret = ops->write(file, buffer, size, file->position, false);
    if (likely(ret.error == 0)) file->position += ret.integer;
    mutex_rel(&file->lock);
    return ret;
}

int vfs_fflags(file_t *file, int flags) {
    mutex_acq(&file->lock, 0, false);

    int old = file->flags;
    if (flags >= 0) file->flags = (old & FILE_PERM_FLAGS) | (flags & (FILE_DESC_FLAGS & ~FILE_PERM_FLAGS));

    mutex_rel(&file->lock);
    return old & FILE_DESC_FLAGS;
}

static size_t try_get_fpath(dentry_t *root, dentry_t *entry, void *buffer, size_t size) {
    size_t total = 0;

    dentry_ref(entry);

    for (;;) {
        mutex_acq(&entry->lock, 0, false);

        if (entry == root) {
            mutex_rel(&entry->lock);

            if (total == 0) {
                if (size != 0) *(char *)(buffer + (size - 1)) = '/';
                total += 1;
            }

            return total;
        }

        if (entry->parent != NULL) {
            size_t clen = entry->name.size + 1;

            if (size >= clen) {
                size -= clen;
                *(char *)(buffer + size) = '/';
                memcpy(buffer + size + 1, entry->name.data, entry->name.size);
            }

            total += clen;

            dentry_t *parent = entry->parent;
            dentry_ref(parent);
            mutex_rel(&entry->lock);
            dentry_deref(entry);
            mutex_acq(&parent->lock, 0, false);
            entry = parent;
        } else {
            dentry_t *mountpoint = entry->fs->mountpoint;
            dentry_ref(mountpoint);
            mutex_rel(&entry->lock);
            dentry_deref(entry);
            mutex_acq(&mountpoint->lock, 0, false);
            entry = mountpoint;
        }
    }
}

hydrogen_ret_t vfs_fpath(dentry_t *path, void **buf_out, size_t *len_out) {
    rcu_state_t state = rcu_read_lock();
    dentry_t *root = current_thread->process->root_dir;
    dentry_ref(root);
    rcu_read_unlock(state);

    void *buffer = NULL;
    size_t capacity = 0;

    for (;;) {
        size_t len = try_get_fpath(root, path, buffer, capacity);

        if (len <= capacity) {
            memmove(buffer, buffer + (capacity - len), len);
            *buf_out = buffer;
            *len_out = len;
            return ret_integer(capacity);
        }

        vfree(buffer, capacity);
        buffer = vmalloc(len);
        capacity = len;

        if (unlikely(!buffer)) {
            return ret_error(ENOMEM);
        }
    }
}

void dentry_ref(dentry_t *entry) {
    __atomic_fetch_add(&entry->references, 1, __ATOMIC_ACQUIRE);
}

void dentry_deref(dentry_t *entry) {
    while (__atomic_fetch_sub(&entry->references, 1, __ATOMIC_ACQ_REL) == 1) {
        dentry_t *parent = entry->parent;

        if (parent != NULL) {
            mutex_acq(&parent->lock, 0, false);

            if (__atomic_load_n(&entry->references, __ATOMIC_RELAXED) != 0) {
                mutex_rel(&parent->lock);
                break;
            }

            // we hold the parent lock, ref count is zero, and can only increase from zero while holding the parent
            // lock. remove it from the parent, and then we can safely free it.

            remove_from_parent(entry);

            mutex_rel(&parent->lock);
        }

        ASSERT(entry != &root_dentry);
        ASSERT(entry->count == 0);
        ASSERT(entry->mounted == NULL);

        vfree(entry->name.data, entry->name.size);
        vfree(entry, sizeof(*entry));

        if (!parent) break;
        entry = parent;
    }
}

void inode_ref(inode_t *inode) {
    ref_inc(&inode->references);
}

void inode_deref(inode_t *inode) {
    if (ref_dec(&inode->references)) {
        if (inode->type == HYDROGEN_SYMLINK) {
            vfree(inode->symlink, inode->size);
        }

        inode->ops->free(inode);
    }
}

uint64_t get_next_fs_id(void) {
    static uint64_t next = 1;
    return __atomic_fetch_add(&next, 1, __ATOMIC_RELAXED);
}

void init_new_inode(inode_t *directory, inode_t *inode, ident_t *ident, uint32_t mode) {
    inode->references = REF_INIT(1);
    inode->atime = get_current_timestamp();
    inode->btime = inode->atime;
    inode->ctime = inode->atime;
    inode->mtime = inode->atime;
    inode->mode = mode;
    inode->uid = ident->uid;
    inode->gid = ident->gid;

    if (directory != NULL && (directory->mode & __S_ISGID) != 0) {
        inode->gid = directory->gid;
        if (inode->type == HYDROGEN_DIRECTORY) inode->mode |= __S_ISGID;
    }

    if (inode->type == HYDROGEN_DIRECTORY) {
        inode->links = directory ? 1 : 2; // for . (and .. if root)
    }
}

int create_root_dentry(filesystem_t *fs, inode_t *root) {
    dentry_t *entry = vmalloc(sizeof(*entry));
    if (unlikely(!entry)) return ENOMEM;
    memset(entry, 0, sizeof(*entry));

    entry->references = 1;
    entry->fs = fs;
    entry->inode = root;
    entry->present = true;

    fs->root = entry;
    return 0;
}
