#include "init/init.h"
#include "hydrogen/handle.h"
#include "hydrogen/init.h"
#include "hydrogen/memory.h"
#include "init/main.h"
#include "kernel/compiler.h"
#include "kernel/pgsize.h"
#include "limine.h"
#include "mem/pmm.h"
#include "sections.h"
#include "string.h"
#include "sys/elf.h"
#include "sys/usermem.h"
#include "util/logging.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

#define INIT_STACK_SIZE 0x800000

static LIMINE_REQ struct limine_module_request module_req = {.id = LIMINE_MODULE_REQUEST};
static LIMINE_REQ struct limine_executable_file_request kfile_req = {.id = LIMINE_EXECUTABLE_FILE_REQUEST};

static uint64_t next_module_idx;
static uintptr_t exec_phdrs = -1;
static size_t exec_phent;
static size_t exec_phnum;
static uintptr_t exec_entry;
static uintptr_t interp_base = -1;

static const uint8_t wanted_elf_ident[] = {0x7f, 'E', 'L', 'F', ELF_CLASS, ELF_DATA, ELF_VERSION};

static void *next_module(void) {
    if (next_module_idx >= module_req.response->module_count) return NULL;
    return module_req.response->modules[next_module_idx++]->address;
}

static void verify_image(elf_header_t *image) {
    if (image->version != ELF_VERSION) panic("invalid image version");
    if (image->type != ET_EXEC && image->type != ET_DYN) panic("invalid image type");
    if (image->machine != ELF_MACHINE) panic("invalid image machine");
}

static intptr_t get_image_slide(hydrogen_handle_t vm, elf_header_t *image) {
    uintptr_t min_addr = -1;
    uintptr_t max_addr = 0;

    for (size_t i = 0; i < image->phnum; i++) {
        elf_segment_t *segment = (void *)image + image->phoff + i * image->phentsize;
        if (segment->type != PT_LOAD || segment->memsz == 0) continue;
        if (segment->align != PAGE_SIZE) panic("unsatisfiable segment alignment");

        uintptr_t min = segment->vaddr & ~PAGE_MASK;
        uintptr_t max = (segment->vaddr + segment->memsz + PAGE_MASK) & ~PAGE_MASK;
        if (max < min) panic("segment vaddr overflow");

        if (min < min_addr) min_addr = min;
        if (max > max_addr) max_addr = max;
    }

    if (min_addr >= max_addr) panic("no loadable segments in image");

    uintptr_t addr = image->type == ET_EXEC ? min_addr : 0;
    int error = hydrogen_vm_map(
            vm,
            &addr,
            max_addr - min_addr,
            image->type == ET_EXEC ? HYDROGEN_MEM_EXACT : 0,
            NULL,
            0
    );
    if (unlikely(error)) panic("failed to find suitable map location for image");

    return (intptr_t)addr - (intptr_t)min_addr;
}

static bool map_image(hydrogen_handle_t vm, elf_header_t *image, intptr_t slide, bool is_interp) {
    bool have_interp = false;

    for (size_t i = 0; i < image->phnum; i++) {
        elf_segment_t *segment = (void *)image + image->phoff + i * image->phentsize;

        if (segment->type != PT_LOAD || segment->memsz == 0) {
            if (!is_interp) {
                if (segment->type == PT_INTERP) have_interp = true;
                else if (segment->type == PT_PHDR) exec_phdrs = segment->vaddr + slide;
            }

            continue;
        }

        uintptr_t offset = segment->vaddr & PAGE_MASK;

        uintptr_t addr = segment->vaddr - offset + slide;
        size_t size = (segment->memsz + offset + PAGE_MASK) & ~PAGE_MASK;

        hydrogen_mem_flags_t flags = HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE | HYDROGEN_MEM_SHARED;
        if (segment->flags & PF_R) flags |= HYDROGEN_MEM_READ;
        if (segment->flags & PF_W) flags |= HYDROGEN_MEM_WRITE;
        if (segment->flags & PF_X) flags |= HYDROGEN_MEM_EXEC;

        if (segment->filesz) {
            size_t available = segment->filesz + offset;
            size_t zero_size = segment->memsz + offset;
            size_t map_size = (available + PAGE_MASK) & ~PAGE_MASK;
            if (zero_size > map_size) zero_size = map_size;

            // don't share memory that needs to be zeroed, because the underlying file might have important data there
            hydrogen_mem_flags_t zero_flags = (flags | HYDROGEN_MEM_WRITE) & ~HYDROGEN_MEM_SHARED;

            size_t imm_size = available == zero_size ? map_size : map_size - PAGE_SIZE;

            // map pages that don't need to be partially zeroed immediately
            if (imm_size) {
                int error = hydrogen_vm_map(
                        vm,
                        &addr,
                        imm_size,
                        flags,
                        init_info.ram_handle,
                        virt_to_phys(image) + (segment->offset - offset)
                );
                if (unlikely(error)) panic("failed to map segment file data (%d)", error);

                addr += imm_size;
                size -= imm_size;
                available -= imm_size;
                zero_size -= imm_size;
                map_size -= imm_size;
            }

            // map pages that do need to be partially zeroed with write permissions, zero them, then protect
            if (map_size) {
                int error = hydrogen_vm_map(
                        vm,
                        &addr,
                        map_size,
                        zero_flags,
                        init_info.ram_handle,
                        virt_to_phys(image) + (segment->offset - offset) + imm_size
                );
                if (unlikely(error)) panic("failed to map segment file data (%d)", error);

                error = hydrogen_vm_fill(vm, addr + available, 0, zero_size - available);
                if (unlikely(error)) panic("failed to zero-fill segment (%d)", error);

                if ((flags & ~HYDROGEN_MEM_SHARED) != zero_flags) {
                    error = hydrogen_vm_remap(vm, addr, map_size, flags);
                    if (unlikely(error)) panic("failed to set segment protection (%d)", error);
                }

                addr += map_size;
                size -= map_size;
            }
        }

        // map pages that are fully zero anonymously
        if (size) {
            int error = hydrogen_vm_map(vm, &addr, size, flags & ~HYDROGEN_MEM_SHARED, NULL, 0);
            if (unlikely(error)) panic("failed to map segment zero data (%d)", error);
        }
    }

    if (have_interp && exec_phdrs == UINTPTR_MAX) panic("no PT_PHDR in executable image with PT_INTERP");

    exec_phent = image->phentsize;
    exec_phnum = image->phnum;

    return have_interp;
}

static uintptr_t load_image(hydrogen_handle_t vm, void *image) {
    bool is_interp = false;

    for (;;) {
        if (!image) panic("no image to load");
        if (memcmp(image, wanted_elf_ident, sizeof(wanted_elf_ident))) panic("invalid image header");

        verify_image(image);
        intptr_t slide = get_image_slide(vm, image);
        if (is_interp) interp_base = slide;

        uintptr_t entry = ((elf_header_t *)image)->entry + slide;
        if (!map_image(vm, image, slide, is_interp)) return entry;
        exec_entry = entry;

        printk("init: loading interpreter\n");
        image = next_module();
        is_interp = true;
    }
}

uintptr_t load_init_image(hydrogen_handle_t vm) {
    if (!module_req.response) panic("no response to module request");

    printk("init: loading init executable\n");
    return load_image(vm, next_module());
}

static void parse_cmdline(void (*handler)(char *, size_t, void *), void *ctx) {
    char *path = module_req.response->modules[0]->path;
    handler(path, strlen(path), ctx);

    if (!kfile_req.response) return;

    char *start = kfile_req.response->executable_file->string;
    char *cur = start;
    char quote = 0;

    for (;;) {
        char c = *cur;

        if (c == 0 || c == quote || (quote == 0 && c == ' ')) {
            *cur = 0;

            if (start != cur || quote != 0) {
                handler(start, cur - start, ctx);
            }

            if (c == 0) break;
            cur++;
            start = cur;
            quote = 0;
            continue;
        }

        if (start == cur && quote == 0 && (c == '"' || c == '\'')) {
            cur++;
            start = cur;
            quote = c;
            continue;
        }

        cur++;
    }
}

struct stack_ctx {
    uintptr_t area;
    size_t rem;
    uintptr_t ibarea;
    size_t ibrem;
    size_t ibalign;
    size_t argc;
};

static void write_data(struct stack_ctx *ctx, const void *data, size_t size) {
    size_t cur = ctx->rem;
    if (cur > size) cur = size;

    if (cur != 0) {
        int error = memcpy_user((void *)ctx->area, data, cur);
        if (unlikely(error)) panic("failed to write data to init stack (%d)", error);
        ctx->rem -= cur;
    }

    ctx->area += size;
}

static uintptr_t write_ibdata(struct stack_ctx *ctx, const void *data, size_t size, size_t align) {
    ASSERT(!((align - 1) & align));

    uintptr_t addr = (ctx->ibarea + (align - 1)) & ~(align - 1);

    size_t pad = addr - ctx->ibarea;
    size_t tot = pad + size;
    size_t cur = ctx->ibrem;
    if (cur > tot) cur = tot;

    ctx->ibarea = addr;

    if (cur > pad) {
        int error = memcpy_user((void *)ctx->ibarea, data, cur - pad);
        if (unlikely(error)) panic("failed to write data to init info block (%d)", error);
    }

    ctx->ibarea += size;
    ctx->ibrem -= cur;

    if (align > ctx->ibalign) ctx->ibalign = align;

    return addr;
}

static void write_arg(char *text, size_t len, void *ptr) {
    struct stack_ctx *ctx = ptr;

    uintptr_t addr = write_ibdata(ctx, text, len + 1, 1);
    write_data(ctx, &addr, sizeof(addr));

    ctx->argc += 1;
}

static void write_auxv(struct stack_ctx *ctx, uintptr_t tag, uintptr_t value) {
    elf_auxv_t auxv = {tag, value};
    write_data(ctx, &auxv, sizeof(auxv));
}

static void write_init_data(struct stack_ctx *ctx, uintptr_t vdso_addr) {
    uintptr_t init_info_addr = write_ibdata(ctx, &init_info, sizeof(init_info), _Alignof(__typeof__(init_info)));

    uintptr_t zero = 0;
    write_data(ctx, &ctx->argc, sizeof(ctx->argc));
    parse_cmdline(write_arg, ctx);
    write_data(ctx, &zero, sizeof(zero)); // argv terminator
    write_data(ctx, &zero, sizeof(zero)); // envp terminator

    write_auxv(ctx, AT_SYSINFO_EHDR, vdso_addr);

    if (interp_base != UINTPTR_MAX) {
        write_auxv(ctx, AT_BASE, interp_base);
        write_auxv(ctx, AT_ENTRY, exec_entry);
        write_auxv(ctx, AT_PHDR, exec_phdrs);
        write_auxv(ctx, AT_PHENT, exec_phent);
        write_auxv(ctx, AT_PHNUM, exec_phnum);
    }

    write_auxv(ctx, HYDROGEN_AT_INIT_INFO, init_info_addr);
    write_auxv(ctx, AT_NULL, 0);
}

uintptr_t create_init_stack(uintptr_t vdso_addr) {
    // determine argc, info block alignment, and init data size
    struct stack_ctx ctx = {.ibalign = 1};
    write_init_data(&ctx, vdso_addr);

    // determine the various offsets and the total stack size
    size_t info_block_off = (ctx.area + (ctx.ibalign - 1)) & ~(ctx.ibalign - 1);
    size_t init_data_offs = (info_block_off + ctx.ibarea + 15) & ~15;
    size_t stack_size = (INIT_STACK_SIZE + init_data_offs + PAGE_MASK) & ~PAGE_MASK;

    // allocate an area for the stack and its guard page
    uintptr_t addr = 0;
    int error = hydrogen_vm_map(NULL, &addr, stack_size + PAGE_SIZE, 0, NULL, 0);
    if (unlikely(error)) panic("failed to allocate area for init stack");

    // allocate the actual stack
    addr += PAGE_SIZE;
    error = hydrogen_vm_map(
            NULL,
            &addr,
            stack_size,
            HYDROGEN_MEM_READ | HYDROGEN_MEM_WRITE | HYDROGEN_MEM_EXACT | HYDROGEN_MEM_OVERWRITE,
            NULL,
            0
    );
    if (unlikely(error)) panic("failed to allocate init stack");

    uintptr_t stack_top = addr + stack_size - init_data_offs;

    // write the init data to the stack
    ctx.rem = ctx.area;
    ctx.area = stack_top;
    ctx.ibrem = ctx.ibarea;
    ctx.ibarea = stack_top + info_block_off;
    write_init_data(&ctx, vdso_addr);

    return stack_top;
}
