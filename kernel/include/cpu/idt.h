#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t rax;
    size_t rbx;
    size_t rcx;
    size_t rdx;
    size_t rsi;
    size_t rdi;
    size_t rbp;
    size_t r8;
    size_t r9;
    size_t r10;
    size_t r11;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
    size_t vector;
    size_t error_code;
    size_t rip;
    size_t cs;
    size_t rflags;
    size_t rsp;
    size_t ss;
} __attribute__((packed, aligned(16))) idt_frame_t;

typedef void (*idt_handler_t)(idt_frame_t *, void *);

void init_idt(void);

void setup_idt(void);

void idt_install(int vector, idt_handler_t handler, void *ctx);

void idt_uninstall(int vector, idt_handler_t handler);

bool idt_paranoid_entry(idt_frame_t *frame);

// `ret` must be the value returned by `idt_paranoid_entry`
void idt_paranoid_exit(bool ret);
