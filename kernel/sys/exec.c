#include "sys/exec.h"
#include "arch/elf.h"
#include "arch/usercopy.h"
#include "cpu/cpudata.h"
#include "errno.h"
#include "fs/vfs.h"
#include "hydrogen/filesystem.h"
#include "hydrogen/memory.h"
#include "hydrogen/signal.h"
#include "hydrogen/types.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "kernel/return.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/mutex.h"
#include "proc/process.h"
#include "string.h"
#include "sys/elf.h"
#include "sys/syscall.h"
#include "util/handle.h"
#include "util/object.h"
#include <stdint.h>

#define USER_STACK_SIZE 0x800000

typedef struct {
    uintptr_t entrypoint;
    uintptr_t image_entry;
    uintptr_t base;
    uintptr_t phdr;
    size_t phdrent;
    size_t phdrnum;
} image_info_t;

static int read_fully(file_t *file, void *buffer, size_t size, uint64_t position) {
    while (size != 0) {
        hydrogen_ret_t ret = vfs_pread(file, buffer, size, position);

        if (unlikely(ret.error)) return ret.error;
        if (unlikely(ret.integer == 0)) return ENOEXEC;

        buffer += ret.integer;
        size -= ret.integer;
        position += ret.integer;
    }

    return 0;
}

static const unsigned char wanted_ident[] =
        {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASSNATIVE, ELFDATANATIVE, EV_CURRENT};

static int load_image(image_info_t *out, vmm_t *vmm, file_t *file, ident_t *ident, bool is_interp) {
    if (unlikely(file->inode->type != HYDROGEN_REGULAR_FILE)) return EACCES;

    mutex_acq(&file->inode->lock, 0, false);
    int error = access_inode(file->inode, ident, HYDROGEN_FILE_EXEC, false);
    mutex_rel(&file->inode->lock);
    if (unlikely(error)) return error;

    elf_header_t header;
    error = read_fully(file, &header, sizeof(header), 0);
    if (unlikely(error)) return error;

    if (memcmp(header.ident, wanted_ident, sizeof(wanted_ident))) return ENOEXEC;
    if (header.type != ET_EXEC && header.type != ET_DYN) return ENOEXEC;
    if (header.machine != EM_NATIVE) return ENOEXEC;
    if (header.version != EV_CURRENT) return ENOEXEC;

    size_t phdrs_size = (size_t)header.phnum * header.phentsize;
    void *buffer = vmalloc(phdrs_size);
    if (unlikely(!buffer)) return ENOMEM;

    error = read_fully(file, buffer, phdrs_size, header.phoff);
    if (unlikely(error)) {
        vfree(buffer, phdrs_size);
        return ENOMEM;
    }

    uintptr_t static_head = UINTPTR_MAX;
    uintptr_t static_tail = 0;

    for (size_t i = 0; i < header.phnum; i++) {
        elf_phdr_t phdr;
        memcpy(&phdr, buffer + i * header.phentsize, header.phentsize);

        if (phdr.filesz > phdr.memsz) {
            vfree(buffer, phdrs_size);
            return ENOEXEC;
        }
        if (phdr.type != PT_LOAD) continue;
        if (phdr.memsz == 0) continue;

        uintptr_t head = phdr.vaddr;
        uintptr_t tail = head + (phdr.memsz - 1);
        if (tail < head) {
            vfree(buffer, phdrs_size);
            return ENOEXEC;
        }

        if (head < static_head) static_head = head;
        if (tail > static_tail) static_tail = tail;
    }

    if (static_head > static_tail) {
        // No PT_LOAD segments
        vfree(buffer, phdrs_size);
        return ENOEXEC;
    }

    static_head &= ~PAGE_MASK;
    static_tail |= PAGE_MASK;
    size_t image_cover = static_tail - static_head + 1;

    uint32_t cover_flags = HYDROGEN_MEM_LAZY_RESERVE;
    if (header.type == ET_EXEC) cover_flags |= HYDROGEN_MEM_EXACT;
    hydrogen_ret_t ret = vmm_map(vmm, static_head, image_cover, cover_flags, NULL, 0, 0);
    error = ret.error;
    if (unlikely(error)) goto err;
    out->base = ret.integer - static_head;

    vmm_t *old = vmm_switch(vmm);

    uint64_t interp_offset = 0;
    size_t interp_file_size = 0;
    size_t interp_size = 0;
    bool have_interp = false;
    bool have_phdr = false;

    for (size_t i = 0; i < header.phnum; i++) {
        elf_phdr_t phdr;
        memcpy(&phdr, buffer + i * header.phentsize, header.phentsize);

        if (phdr.type == PT_INTERP) {
            if (have_interp || is_interp) {
                error = ENOEXEC;
                goto err2;
            }

            interp_offset = phdr.offset;
            interp_file_size = phdr.filesz;
            interp_size = phdr.memsz;
            have_interp = true;
            continue;
        } else if (phdr.type == PT_PHDR) {
            if (have_phdr) {
                error = ENOEXEC;
                goto err2;
            }
            if (!is_interp) out->phdr = phdr.vaddr + out->base;
            have_phdr = true;
            continue;
        } else if (phdr.type != PT_LOAD) {
            continue;
        }

        if (phdr.memsz == 0) continue;

        uint32_t flags = HYDROGEN_MEM_OVERWRITE | HYDROGEN_MEM_EXACT;

        if (phdr.flags & PF_R) flags |= HYDROGEN_MEM_READ;
        if (phdr.flags & PF_W) flags |= HYDROGEN_MEM_WRITE;
        if (phdr.flags & PF_X) flags |= HYDROGEN_MEM_EXEC;
        if ((flags & HYDROGEN_MEM_WRITE) == 0) flags |= HYDROGEN_MEM_SHARED;

        uintptr_t head = phdr.vaddr + out->base;
        uintptr_t zero_tail = head + (phdr.memsz - 1);
        uintptr_t tail = zero_tail | PAGE_MASK;
        size_t offset = head & PAGE_MASK;
        head -= offset;

        if (phdr.filesz != 0) {
            uintptr_t file_tail = head + offset + (phdr.filesz - 1);
            uintptr_t file_map_tail = file_tail | PAGE_MASK;
            uint64_t file_offs = phdr.offset - offset;

            if ((flags & HYDROGEN_MEM_WRITE) != 0 || file_tail == zero_tail || file_tail == file_map_tail ||
                (file_map_tail - head) > PAGE_MASK) {
                size_t map_size = file_map_tail - head + 1;

                if ((flags & HYDROGEN_MEM_WRITE) == 0 && file_tail != zero_tail && file_tail != file_map_tail) {
                    map_size -= PAGE_SIZE;
                }

                ret = vfs_mmap(
                        file,
                        HYDROGEN_MEM_OBJECT_READ | HYDROGEN_MEM_OBJECT_EXEC,
                        vmm,
                        head,
                        map_size,
                        flags,
                        file_offs
                );
                error = ret.error;
                if (unlikely(error)) goto err2;

                head += map_size;
                file_offs += map_size;
            }

            if (head < file_map_tail) {
                ret = vfs_mmap(
                        file,
                        HYDROGEN_MEM_OBJECT_READ | HYDROGEN_MEM_OBJECT_EXEC,
                        vmm,
                        head,
                        (file_map_tail - head) + 1,
                        (flags & ~HYDROGEN_MEM_SHARED) | HYDROGEN_MEM_WRITE,
                        file_offs
                );
                error = ret.error;
                if (unlikely(error)) goto err2;
            }

            if (file_tail != zero_tail) {
                uintptr_t max = file_map_tail < zero_tail ? file_map_tail : zero_tail;
                error = user_memset((void *)file_tail, 0, max - file_tail);
                if (unlikely(error)) goto err2;
            }

            if (head < file_map_tail) {
                error = vmm_remap(
                        vmm,
                        head,
                        file_map_tail - head + 1,
                        flags & (HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXEC)
                );
                if (unlikely(error)) goto err2;
                head = file_map_tail + 1;
            }
        }

        if (head < tail) {
            ret = vmm_map(vmm, head, tail - head + 1, flags & ~HYDROGEN_MEM_SHARED, NULL, 0, 0);
            error = ret.error;
            if (unlikely(error)) goto err2;
        }
    }

    vmm_switch(old);
    vfree(buffer, phdrs_size);

    out->entrypoint = header.entry + out->base;

    if (!is_interp) {
        out->image_entry = out->entrypoint;
        out->phdrent = header.phentsize;
        out->phdrnum = header.phnum;
    }

    if (have_interp) {
        void *path = vmalloc(interp_size);
        if (unlikely(!path)) return ENOMEM;

        error = read_fully(file, path, interp_file_size, interp_offset);
        if (unlikely(error)) {
            vfree(path, interp_size);
            return error;
        }

        memset(path + interp_file_size, 0, interp_size - interp_file_size);

        file_t *interp;
        error = vfs_open(&interp, NULL, path, strlen(path), 0, 0, ident);
        vfree(path, interp_size);
        if (unlikely(error)) return error;

        error = load_image(out, vmm, interp, ident, true);
        obj_deref(&interp->base);
        if (unlikely(error)) return error;
    }

    return 0;
err2:
    vmm_switch(old);
err:
    vfree(buffer, phdrs_size);
    return error;
}

typedef struct {
    uintptr_t base;
    size_t remaining;
    size_t total;
    size_t align;
} stack_area_t;

typedef struct {
    stack_area_t main, blob;
} stack_build_ctx_t;

#define BUFFER_SIZE 1024

static hydrogen_ret_t area_write(stack_area_t *area, const void *data, size_t size, size_t align, vmm_t *src) {
    uintptr_t addr = (area->base + (align - 1)) & ~(align - 1);
    size_t padding = addr - area->base;
    size_t totsize = padding + size;

    area->total += totsize;
    if (area->total < totsize) return ret_error(ENOMEM);
    if (align > area->align) area->align = align;
    if (totsize > area->remaining) return ret_integer(addr);

    if (!src) {
        int error = user_memcpy((void *)addr, data, size);
        if (unlikely(error)) return ret_error(error);
        area->base += totsize;
        area->remaining -= totsize;
        return ret_integer(addr);
    }

    unsigned char buffer[BUFFER_SIZE];
    uintptr_t dest = addr;

    while (size) {
        size_t cur = sizeof(buffer) < size ? sizeof(buffer) : size;

        vmm_t *prev = vmm_switch(src);
        int error = user_memcpy(buffer, data, cur);
        vmm_switch(prev);
        if (unlikely(error)) return ret_error(error);

        error = user_memcpy((void *)dest, buffer, cur);
        if (unlikely(error)) return ret_error(error);

        data += cur;
        dest += cur;
        size -= cur;
    }

    area->base += totsize;
    area->remaining -= totsize;
    return ret_integer(addr);
}

static int build_string_list(stack_build_ctx_t *ctx, vmm_t *src, size_t count, const hydrogen_string_t *strings) {
    hydrogen_ret_t ret;

    for (size_t i = 0; i < count; i++) {
        if (src) {
            hydrogen_string_t string;
            vmm_t *prev = vmm_switch(src);
            int error = user_memcpy(&string, &strings[i], sizeof(string));
            vmm_switch(prev);
            if (unlikely(error)) return error;

            error = verify_user_buffer(string.data, string.size);
            if (unlikely(error)) return error;

            ret = area_write(&ctx->blob, string.data, string.size, 1, src);
        } else {
            ret = area_write(&ctx->blob, strings[i].data, strings[i].size, 1, NULL);
        }

        if (unlikely(ret.error)) return ret.error;

        uintptr_t pointer = ret.integer;

        char c = 0;
        ret = area_write(&ctx->blob, &c, sizeof(c), 1, NULL);
        if (unlikely(ret.error)) return ret.error;

        ret = area_write(&ctx->main, &pointer, sizeof(pointer), _Alignof(uintptr_t), NULL);
        if (unlikely(ret.error)) return ret.error;
    }

    uintptr_t terminator = 0;
    ret = area_write(&ctx->main, &terminator, sizeof(terminator), _Alignof(uintptr_t), NULL);
    if (unlikely(ret.error)) return ret.error;

    return 0;
}

typedef struct {
    uintptr_t tag;
    uintptr_t value;
} auxv_t;

static int build_stack(
        stack_build_ctx_t *ctx,
        vmm_t *src,
        image_info_t *image,
        uintptr_t vdso,
        bool secure,
        size_t argc,
        const hydrogen_string_t *argv,
        size_t envc,
        const hydrogen_string_t *envp
) {
    hydrogen_ret_t ret = area_write(&ctx->main, &argc, sizeof(argc), _Alignof(size_t), NULL);
    if (unlikely(ret.error)) return ret.error;

    int error = build_string_list(ctx, src, argc, argv);
    if (unlikely(error)) return error;

    error = build_string_list(ctx, src, envc, envp);
    if (unlikely(error)) return error;

    auxv_t aux_vector[8];
    size_t nauxv = 0;

    aux_vector[nauxv++] = (auxv_t){AT_SYSINFO_EHDR, vdso};
    aux_vector[nauxv++] = (auxv_t){AT_SECURE, secure ? 1 : 0};

    if (image->image_entry != image->entrypoint) {
        aux_vector[nauxv++] = (auxv_t){AT_PHDR, image->phdr};
        aux_vector[nauxv++] = (auxv_t){AT_PHENT, image->phdrent};
        aux_vector[nauxv++] = (auxv_t){AT_PHNUM, image->phdrnum};
        aux_vector[nauxv++] = (auxv_t){AT_ENTRY, image->image_entry};
    }

    aux_vector[nauxv++] = (auxv_t){AT_NULL, 0};

    ret = area_write(&ctx->main, aux_vector, nauxv * sizeof(*aux_vector), _Alignof(auxv_t), NULL);
    if (unlikely(ret.error)) return ret.error;

    return 0;
}

static int create_stack(
        uintptr_t *out,
        vmm_t *vmm,
        image_info_t *image,
        uintptr_t vdso,
        bool secure,
        size_t argc,
        const hydrogen_string_t *argv,
        size_t envc,
        const hydrogen_string_t *envp,
        bool user_strings
) {
    vmm_t *old = vmm_switch(vmm);

    stack_build_ctx_t pass1 = {};
    int error = build_stack(&pass1, user_strings ? old : NULL, image, vdso, secure, argc, argv, envc, envp);
    if (unlikely(error)) {
        vmm_switch(old);
        return error;
    }

    size_t blob_offset = (pass1.main.total + (pass1.blob.align - 1)) & ~(pass1.blob.align - 1);
    size_t total_size = (blob_offset + pass1.blob.total + 15) & ~15;
    size_t map_size = ((total_size + PAGE_MASK) & ~PAGE_MASK) + USER_STACK_SIZE;

    hydrogen_ret_t ret = vmm_map(vmm, 0, map_size + PAGE_SIZE, HYDROGEN_MEM_LAZY_RESERVE, NULL, 0, 0);
    if (unlikely(ret.error)) {
        vmm_switch(old);
        return ret.error;
    }

    uintptr_t stack_top = ret.integer + PAGE_SIZE;
    uintptr_t stack_bottom = stack_top + map_size;

    error = vmm_remap(vmm, stack_top, map_size, HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE);
    if (unlikely(error)) {
        vmm_switch(old);
        return ret.error;
    }

    uintptr_t stack_pointer = stack_bottom - total_size;
    stack_build_ctx_t pass2 = {
            .main.base = stack_pointer,
            .main.remaining = pass1.main.total,
            .blob.base = stack_pointer + blob_offset,
            .blob.remaining = pass1.blob.total,
    };
    error = build_stack(&pass2, user_strings ? old : NULL, image, vdso, secure, argc, argv, envc, envp);
    vmm_switch(old);
    if (unlikely(error)) return error;

    ASSERT(pass2.main.total <= pass1.main.total);
    ASSERT(pass2.blob.total <= pass2.blob.total);

    *out = stack_pointer;
    return 0;
}

int create_exec_data(
        exec_data_t *out,
        process_t *process,
        file_t *image,
        ident_t *ident,
        size_t argc,
        const hydrogen_string_t *argv,
        size_t envc,
        const hydrogen_string_t *envp,
        bool user_strings
) {
    vmm_t *vmm;
    int error = vmm_create(&vmm);
    if (unlikely(error)) return error;

    image_info_t image_info;
    error = load_image(&image_info, vmm, image, ident, false);
    if (unlikely(error)) {
        obj_deref(&vmm->base);
        return error;
    }

    hydrogen_ret_t vdso = vmm_map_vdso(vmm);
    if (unlikely(vdso.error)) {
        obj_deref(&vmm->base);
        return vdso.error;
    }

    bool secure = false;
    ident_t *new_ident = ident;
    ident_ref(ident);

    mutex_acq(&image->inode->lock, 0, false);

    if ((image->inode->fs->flags & FILESYSTEM_NO_SETUID) == 0) {
        if (image->inode->mode & (__S_ISUID | __S_ISGID)) {
            secure = true;
            new_ident = ident_copy(ident);
            ident_deref(ident);
        }

        if (image->inode->mode & __S_ISUID) new_ident->euid = image->inode->uid;
        if (image->inode->mode & __S_ISGID) new_ident->egid = image->inode->gid;
    }

    mutex_rel(&image->inode->lock);

    error = create_stack(&out->sp, vmm, &image_info, vdso.integer, secure, argc, argv, envc, envp, user_strings);
    if (unlikely(error)) {
        ident_deref(new_ident);
        obj_deref(&vmm->base);
        return error;
    }

    vmm->path = image->path;
    vmm->inode = image->inode;
    if (vmm->path) dentry_ref(vmm->path);
    inode_ref(vmm->inode);

    out->vmm = vmm;
    out->ident = ident;
    out->pc = image_info.entrypoint;
    return 0;
}

void exec_finalize(exec_data_t *data) {
    process_t *process = current_thread->process;
    __atomic_store_n(&process->did_exec, true, __ATOMIC_RELEASE);

    mutex_acq(&process->ident_update_lock, 0, false);
    ident_t *old = process->identity;
    rcu_write(process->identity, data->ident);
    mutex_rel(&process->ident_update_lock);
    rcu_sync();
    ident_deref(old);

    mutex_acq(&process->sig_lock, 0, false);

    for (int i = 0; i < __NSIG; i++) {
        struct __sigaction *handler = &process->sig_handlers[i];

        if (handler->__func.__handler != __SIG_IGN) handler->__func.__handler = __SIG_DFL;
    }

    mutex_rel(&process->sig_lock);

    namespace_handle_exec(current_thread->namespace);
}

void free_exec_data(exec_data_t *data) {
    if (data->vmm) obj_deref(&data->vmm->base);
    ident_deref(data->ident);
}
