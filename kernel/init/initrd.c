#include "errno.h"
#include "fs/vfs.h"
#include "hydrogen/fcntl.h"
#include "hydrogen/filesystem.h"
#include "hydrogen/types.h"
#include "init/main.h" /* IWYU pragma: keep */
#include "init/task.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/memmap.h"
#include "mem/pmem.h"
#include "sections.h"
#include "string.h"
#include "util/object.h"
#include "util/panic.h"
#include "util/printk.h"
#include <stdint.h>

typedef struct {
    char name[100];
    unsigned char mode[8];
    unsigned char uid[8];
    unsigned char gid[8];
    unsigned char size[12];
    unsigned char mtime[12];
    unsigned char chksum[8];
    unsigned char typeflag;
    char linkname[100];
    unsigned char magic[6];
    unsigned char version[2];
    unsigned char uname[32];
    unsigned char gname[32];
    unsigned char devmajor[8];
    unsigned char devminor[8];
    char prefix[155];
} __attribute__((packed)) ustar_header_t;

static uint64_t parse_oct_field(unsigned char *buf, size_t size) {
    uint64_t value = 0;

    for (size_t i = 0; i < size; i++) {
        unsigned char c = buf[i];
        if (c == 0 || c == ' ') break;
        value = (value * 8) + (c - '0');
    }

    return value;
}

static file_t *open_directory(file_t *dest, void **name_buf, size_t *name_len) {
    char *name_start = *name_buf;
    char *name = name_start;
    size_t len = *name_len;

    while (len > 0 && name[0] == '/') {
        name++;
        len--;
    }

    obj_ref(&dest->base);

    while (len != 0) {
        size_t complen = 1;
        while (complen < len && name[complen] != '/') complen++;

        size_t skiplen = complen;
        while (skiplen < len && name[skiplen] == '/') skiplen++;

        if (skiplen == len) break;

        int error = vfs_create(dest, name, complen, HYDROGEN_DIRECTORY, 0755);
        if (error != 0 && unlikely(error != EEXIST)) {
            printk("initrd: failed to create parent directory %S for %S (%e)\n",
                   name_start,
                   name - name_start + complen,
                   name_start,
                   name - name_start + len,
                   error);
            obj_deref(&dest->base);
            return NULL;
        }

        file_t *child;
        error = vfs_open(&child, dest, name, complen, __O_DIRECTORY, 0);
        obj_deref(&dest->base);
        if (unlikely(error)) {
            printk("initrd: failed to open parent directory %S for %S (%e)\n",
                   name_start,
                   name - name_start + complen,
                   name_start,
                   name - name_start + len,
                   error);
            return NULL;
        }

        dest = child;
        name += skiplen;
        len -= skiplen;
    }

    *name_buf = name;
    *name_len = len;
    return dest;
}

static bool extract_single(file_t *dest, void *data, size_t size) {
    static char magic[] = "ustar";
    NONSTRING static char version[2] = "00";

    unsigned char path_buf[256];

    void *cur_start = data;
    size_t cur_done = 0;
    bool did_anything = false;
    bool errored = false;

    while (cur_done < size) {
        ustar_header_t *header = data;
        data += 512;

        if (memcmp(header->magic, magic, sizeof(magic))) {
            if (!did_anything) {
                printk("initrd: unsupported archive format\n");
                return false;
            }

            break;
        }

        if (memcmp(header->version, version, sizeof(version))) {
            printk("initrd: unsupported ustar version\n");
            return false;
        }

        uint32_t mode = parse_oct_field(header->mode, sizeof(header->mode));
        uint32_t uid = parse_oct_field(header->uid, sizeof(header->uid));
        uint32_t gid = parse_oct_field(header->gid, sizeof(header->gid));
        uint64_t size = parse_oct_field(header->size, sizeof(header->size));

        size_t prefix_len = strnlen(header->prefix, sizeof(header->prefix));
        size_t suffix_len = strnlen(header->name, sizeof(header->name));
        size_t path_len;
        void *path;

        if (prefix_len != 0) {
            memcpy(path_buf, header->prefix, prefix_len);
            path_buf[prefix_len] = '/';
            memcpy(&path_buf[prefix_len + 1], header->name, suffix_len);

            path = path_buf;
            path_len = prefix_len + suffix_len + 1;
        } else {
            path = header->name;
            path_len = suffix_len;
        }

        file_t *parent;
        file_t *file;

        void *name = path;
        size_t name_len = path_len;

        switch (header->typeflag) {
        case 0:
        case '0':
        case '7':
            parent = open_directory(dest, &name, &name_len);

            if (parent) {
                int error = vfs_open(&file, parent, name, name_len, __O_WRONLY | __O_CREAT | __O_EXCL, mode);

                if (error != 0) {
                    printk("initrd: failed to create regular file %S (%e)\n",
                           path,
                           path_len,
                           header->linkname,
                           strnlen(header->linkname, sizeof(header->linkname)),
                           error);
                    file = NULL;
                    errored = true;
                } else {
                    int error = vfs_truncate(file, NULL, 0, size);

                    if (unlikely(errored)) {
                        printk("initrd: failed to set size of regular file %S to %U bytes (%e)\n",
                               path,
                               path_len,
                               size,
                               error);
                        errored = true;
                    } else {
                        uint64_t idx = 0;

                        while (idx < size) {
                            uint64_t cur = size - idx;
                            if (cur > SIZE_MAX) cur = SIZE_MAX;

                            hydrogen_ret_t ret = vfs_write(file, data + idx, cur);
                            if (unlikely(ret.error)) {
                                printk("initrd: failed to write data to regular file %S (%e)\n",
                                       path,
                                       path_len,
                                       ret.error);
                                errored = true;
                                break;
                            }

                            idx += ret.integer;
                        }
                    }
                }

                obj_deref(&parent->base);
            } else {
                file = NULL;
                errored = true;
            }
            break;
        case '1':
            parent = open_directory(dest, &name, &name_len);

            if (parent) {
                int error = vfs_link(
                        parent,
                        name,
                        name_len,
                        dest,
                        header->linkname,
                        strnlen(header->linkname, sizeof(header->linkname)),
                        0
                );

                if (error != 0) {
                    printk("initrd: failed to create hard link %S to %S (%e)\n",
                           path,
                           path_len,
                           header->linkname,
                           strnlen(header->linkname, sizeof(header->linkname)),
                           error);
                    file = NULL;
                    errored = true;
                } else {
                    file = NULL;
                }

                obj_deref(&parent->base);
            } else {
                file = NULL;
                errored = true;
            }
            break;
        case '2':
            parent = open_directory(dest, &name, &name_len);

            if (parent) {
                int error = vfs_symlink(
                        parent,
                        name,
                        name_len,
                        header->linkname,
                        strnlen(header->linkname, sizeof(header->linkname))
                );

                if (error != 0) {
                    printk("initrd: failed to create symlink %S to %S (%e)\n",
                           path,
                           path_len,
                           header->linkname,
                           strnlen(header->linkname, sizeof(header->linkname)),
                           error);
                    file = NULL;
                    errored = true;
                } else {
                    file = NULL;
                }

                obj_deref(&parent->base);
            } else {
                file = NULL;
                errored = true;
            }
            break;
        case '5':
            size = 0;
            parent = open_directory(dest, &name, &name_len);

            if (parent) {
                int error = vfs_create(parent, name, name_len, HYDROGEN_DIRECTORY, mode);

                if (error != 0 && unlikely(error != EEXIST)) {
                    printk("initrd: failed to create directory %S (%e)\n", path, path_len, error);
                    file = NULL;
                    errored = true;
                } else {
                    error = vfs_open(&file, parent, name, name_len, __O_DIRECTORY, 0);

                    if (unlikely(error)) {
                        printk("initrd: failed to open directory %S (%e)\n", path, path_len, error);
                        file = NULL;
                        errored = true;
                    }
                }

                obj_deref(&parent->base);
            } else {
                file = NULL;
                errored = true;
            }
            break;
        case '3':
        case '4':
        case '6': size = 0; // fall through
        default:
            printk("initrd: unknown file type '%c' for %S\n", header->typeflag, path, path_len);
            file = NULL;
            errored = true;
            break;
        }

        if (file) {
            int error = vfs_chmod(file, "", 0, mode, __AT_SYMLINK_NOFOLLOW);
            if (unlikely(error)) {
                printk("initrd: failed to change mode for %S to %o (%e)\n", path, path_len, mode, error);
                errored = true;
            }

            error = vfs_chown(file, "", 0, uid, gid, __AT_SYMLINK_NOFOLLOW);
            if (unlikely(error)) {
                printk("initrd: failed to change owner for %S to %u:%u (%e)\n", path, path_len, uid, gid, error);
                errored = true;
            }

            obj_deref(&file->base);
        }

        data += (size + 511) & ~511;
        cur_done += 512;
        cur_done += (size + 511) & ~511;

        if (cur_done >= PAGE_SIZE) {
            pmem_free_multiple(virt_to_page(cur_start), cur_done >> PAGE_SHIFT);
            pmem_unreserve(cur_done >> PAGE_SHIFT);
            cur_start += cur_done & ~PAGE_MASK;
            cur_done &= PAGE_MASK;
        }

        did_anything = true;
    }

    return !errored;
}

static void extract_initrd(void) {
    static LIMINE_REQ struct limine_module_request module_req = {.id = LIMINE_MODULE_REQUEST};
    if (unlikely(!module_req.response)) return;

    bool errored = false;

    file_t *dest;
    int error = vfs_open(&dest, NULL, "", 0, __O_DIRECTORY, 0);
    if (unlikely(error)) panic("initrd: failed to open destination directory (%e)", error);

    for (uint64_t i = 0; i < module_req.response->module_count; i++) {
        struct limine_file *file = module_req.response->modules[i];
        if (!extract_single(dest, file->address, file->size)) errored = true;
    }

    obj_deref(&dest->base);

    if (errored) panic("initrd: extraction failed");
}

INIT_DEFINE(extract_initrd, extract_initrd, INIT_REFERENCE(mount_rootfs));
