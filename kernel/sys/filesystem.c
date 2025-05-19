#include "hydrogen/filesystem.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "fs/vfs.h"
#include "hydrogen/fcntl.h"
#include "hydrogen/handle.h"
#include "hydrogen/memory.h"
#include "hydrogen/process.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/rcu.h"
#include "sys/memory.h"
#include "sys/process.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

static int file_for_rel(file_t **out, int rel) {
    if (rel != HYDROGEN_INVALID_HANDLE) {
        handle_data_t data;
        int error = hnd_resolve(&data, rel, OBJECT_FILE_DESCRIPTION, 0);
        if (unlikely(error)) return error;
        *out = (file_t *)data.object;
    } else {
        *out = NULL;
    }

    return 0;
}

static int copy_string(void **buf_out, const void *src, size_t len) {
    int error = verify_user_buffer((uintptr_t)src, len);
    if (unlikely(error)) return error;

    void *buf = vmalloc(len);
    if (unlikely(!buf)) return ENOMEM;

    error = user_memcpy(buf, src, len);
    if (unlikely(error)) return error;

    *buf_out = buf;
    return 0;
}

int hydrogen_fs_chdir(int process, int rel, const void *path, size_t length) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_CHDIR);
    if (unlikely(error)) return error;

    file_t *frel;
    error = file_for_rel(&frel, rel);
    if (unlikely(error)) goto ret;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret2;

    error = vfs_chdir(proc, frel, kpath, length);

    vfree(kpath, length);
ret2:
    if (frel) obj_deref(&frel->base);
ret:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

int hydrogen_fs_chroot(int process, int rel, const void *path, size_t length) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_CHROOT);
    if (unlikely(error)) return error;

    file_t *frel;
    error = file_for_rel(&frel, rel);
    if (unlikely(error)) goto ret;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret2;

    error = vfs_chroot(proc, frel, kpath, length);

    vfree(kpath, length);
ret2:
    if (frel) obj_deref(&frel->base);
ret:
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return error;
}

hydrogen_ret_t hydrogen_fs_umask(int process, uint32_t mask) {
    process_t *proc;
    int error = process_or_this(&proc, process, HYDROGEN_PROCESS_UMASK);
    if (unlikely(error)) return ret_error(error);

    mask = vfs_umask(proc, mask);
    if (process != HYDROGEN_THIS_PROCESS) obj_deref(&proc->base);
    return ret_integer(mask);
}

int hydrogen_fs_create(int rel, const void *path, size_t length, hydrogen_file_type_t type, uint32_t mode) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_create(frel, kpath, length, type, mode);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_symlink(int rel, const void *path, size_t length, const void *target, size_t tlength) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    void *ktarget;
    error = copy_string(&ktarget, target, tlength);
    if (unlikely(error)) goto ret2;

    error = vfs_symlink(frel, kpath, length, ktarget, tlength);

    vfree(ktarget, tlength);
ret2:
    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_link(
        int rel,
        const void *path,
        size_t length,
        int trel,
        const void *target,
        size_t tlength,
        int flags
) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    file_t *ftrel;
    error = file_for_rel(&ftrel, trel);
    if (unlikely(error)) goto ret;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret2;

    void *ktarget;
    error = copy_string(&ktarget, target, tlength);
    if (unlikely(error)) goto ret3;

    error = vfs_link(frel, kpath, length, ftrel, ktarget, tlength, flags);

    vfree(ktarget, tlength);
ret3:
    vfree(kpath, length);
ret2:
    if (ftrel) obj_deref(&ftrel->base);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_unlink(int rel, const void *path, size_t length, int flags) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_unlink(frel, kpath, length, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_rename(int rel, const void *path, size_t length, int trel, const void *target, size_t tlen) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    file_t *ftrel;
    error = file_for_rel(&ftrel, trel);
    if (unlikely(error)) goto ret;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret2;

    void *ktarget;
    error = copy_string(&ktarget, target, tlen);
    if (unlikely(error)) goto ret3;

    error = vfs_rename(frel, kpath, length, ftrel, ktarget, tlen);

    vfree(ktarget, tlen);
ret3:
    vfree(kpath, length);
ret2:
    if (ftrel) obj_deref(&ftrel->base);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_access(int rel, const void *path, size_t length, uint32_t type, int flags) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_access(frel, kpath, length, type, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_stat(int rel, const void *path, size_t length, hydrogen_file_information_t *info, int flags) {
    int error = verify_user_buffer((uintptr_t)info, sizeof(*info));
    if (unlikely(error)) return error;

    file_t *frel;
    error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_stat(frel, kpath, length, info, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

hydrogen_ret_t hydrogen_fs_readlink(int rel, const void *path, size_t length, void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *frel;
    error = file_for_rel(&frel, rel);
    if (unlikely(error)) return ret_error(error);

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto err;

    hydrogen_ret_t ret = vfs_readlink(frel, kpath, length, buffer, size);

    vfree(kpath, length);
    return ret;
err:
    if (frel) obj_deref(&frel->base);
    return ret_error(error);
}

int hydrogen_fs_chmod(int rel, const void *path, size_t length, uint32_t mode, int flags) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_chmod(frel, kpath, length, mode, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_chown(int rel, const void *path, size_t length, uint32_t uid, uint32_t gid, int flags) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_chown(frel, kpath, length, uid, gid, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_utime(
        int rel,
        const void *path,
        size_t length,
        __int128_t atime,
        __int128_t ctime,
        __int128_t mtime,
        int flags
) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_utime(frel, kpath, length, atime, ctime, mtime, flags);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

int hydrogen_fs_truncate(int rel, const void *path, size_t length, uint64_t size) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return error;

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto ret;

    error = vfs_truncate(frel, kpath, length, size);

    vfree(kpath, length);
ret:
    if (frel) obj_deref(&frel->base);
    return error;
}

hydrogen_ret_t hydrogen_fs_open(int rel, const void *path, size_t length, int flags, uint32_t mode) {
    file_t *frel;
    int error = file_for_rel(&frel, rel);
    if (unlikely(error)) return ret_error(error);

    void *kpath;
    error = copy_string(&kpath, path, length);
    if (unlikely(error)) goto err;

    error = hnd_reserve(current_thread->namespace);
    if (unlikely(error)) goto err2;

    handle_data_t *data = vmalloc(sizeof(*data));
    if (unlikely(!data)) {
        error = ENOMEM;
        goto err3;
    }

    file_t *file;
    ident_t *ident = ident_get(current_thread->process);
    error = vfs_open(&file, frel, kpath, length, flags, mode, ident);
    ident_deref(ident);
    if (unlikely(error)) goto err4;

    object_rights_t rights = 0;
    if (flags & __O_RDONLY) rights |= HYDROGEN_FILE_READ;
    if (flags & __O_WRONLY) rights |= HYDROGEN_FILE_WRITE;

    uint32_t handle_flags = 0;
    if ((flags & __O_CLOFORK) == 0) handle_flags |= HYDROGEN_HANDLE_CLONE_KEEP;
    if ((flags & __O_CLOEXEC) == 0) handle_flags |= HYDROGEN_HANDLE_EXEC_KEEP;
    int handle = hnd_alloc_reserved(current_thread->namespace, &file->base, rights, handle_flags, data);

    vfree(kpath, length);
    if (frel) obj_deref(&frel->base);
    return ret_integer(handle);
err4:
    vfree(data, sizeof(*data));
err3:
    hnd_unreserve(current_thread->namespace);
err2:
    vfree(kpath, length);
err:
    if (frel) obj_deref(&frel->base);
    return ret_error(error);
}

hydrogen_ret_t hydrogen_fs_mmap(int file, int vmm_hnd, uintptr_t hint, size_t size, uint32_t flags, uint64_t offset) {
    handle_data_t data;
    int error = hnd_resolve(&data, file, OBJECT_FILE_DESCRIPTION, 0);
    if (unlikely(error)) return ret_error(error);

    vmm_t *vmm;
    error = vmm_or_this(&vmm, vmm_hnd, HYDROGEN_VMM_MAP);
    if (unlikely(error)) {
        obj_deref(data.object);
        return ret_error(error);
    }

    object_rights_t mem_rights = 0;

    if (data.rights & HYDROGEN_FILE_READ) {
        mem_rights |= HYDROGEN_MEM_OBJECT_READ | HYDROGEN_MEM_OBJECT_EXEC;

        if (data.rights & HYDROGEN_FILE_WRITE) {
            mem_rights |= HYDROGEN_MEM_OBJECT_WRITE;
        }
    }

    hydrogen_ret_t ret = vfs_mmap((file_t *)data.object, mem_rights, vmm, hint, size, flags, offset);
    if (vmm_hnd != HYDROGEN_THIS_VMM) obj_deref(&vmm->base);
    obj_deref(data.object);
    return ret;
}

static int file_resolve(file_t **out, int file, object_rights_t rights) {
    handle_data_t data;
    int error = hnd_resolve(&data, file, OBJECT_FILE_DESCRIPTION, rights);
    if (unlikely(error)) return error;
    *out = (file_t *)data.object;
    return 0;
}

hydrogen_ret_t hydrogen_fs_pread(int file, void *buffer, size_t size, uint64_t position) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    error = file_resolve(&fdesc, file, HYDROGEN_FILE_READ);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_pread(fdesc, buffer, size, position);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_pwrite(int file, const void *buffer, size_t size, uint64_t position) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    error = file_resolve(&fdesc, file, HYDROGEN_FILE_WRITE);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_pwrite(fdesc, buffer, size, position);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_seek(int file, hydrogen_seek_anchor_t anchor, int64_t offset) {
    file_t *fdesc;
    int error = file_resolve(&fdesc, file, 0);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_seek(fdesc, anchor, offset);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_readdir(int file, void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    error = file_resolve(&fdesc, file, HYDROGEN_FILE_READ);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_readdir(fdesc, buffer, size);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_read(int file, void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    error = file_resolve(&fdesc, file, HYDROGEN_FILE_READ);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_read(fdesc, buffer, size);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_write(int file, const void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    error = file_resolve(&fdesc, file, HYDROGEN_FILE_WRITE);
    if (unlikely(error)) return ret_error(error);

    hydrogen_ret_t ret = vfs_write(fdesc, buffer, size);
    obj_deref(&fdesc->base);
    return ret;
}

hydrogen_ret_t hydrogen_fs_fflags(int file, int flags) {
    file_t *fdesc;
    int error = file_resolve(&fdesc, file, 0);
    if (unlikely(error)) return ret_error(error);

    flags = vfs_fflags(fdesc, flags);
    obj_deref(&fdesc->base);
    return ret_integer(flags);
}

hydrogen_ret_t hydrogen_fs_fpath(int file, void *buffer, size_t size) {
    int error = verify_user_buffer((uintptr_t)buffer, size);
    if (unlikely(error)) return ret_error(error);

    file_t *fdesc;
    dentry_t *entry;

    if (file != HYDROGEN_INVALID_HANDLE) {
        error = file_resolve(&fdesc, file, 0);
        if (unlikely(error)) return ret_error(error);
        entry = fdesc->path;
    } else {
        fdesc = NULL;
        rcu_state_t state = rcu_read_lock();
        entry = current_thread->process->work_dir;
        dentry_ref(entry);
        rcu_read_unlock(state);
    }

    void *path;
    size_t length;
    hydrogen_ret_t ret = vfs_fpath(entry, &path, &length);

    if (fdesc) obj_deref(&fdesc->base);
    else dentry_deref(entry);

    if (unlikely(ret.error)) return ret;

    error = user_memcpy(buffer, path, size < length ? size : length);
    vfree(path, ret.integer);
    if (unlikely(error)) return ret_error(error);

    return ret_integer(length);
}
