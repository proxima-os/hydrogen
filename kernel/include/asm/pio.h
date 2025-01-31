#pragma once

#include <stddef.h>
#include <stdint.h>

static inline void outb(uint16_t port, uint8_t value) {
    asm("outb %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline void outw(uint16_t port, uint16_t value) {
    asm("outw %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline void outl(uint16_t port, uint32_t value) {
    asm("outl %0, %1" ::"a"(value), "Nd"(port) : "memory");
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    asm("inb %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t value;
    asm("inw %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t value;
    asm("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
    return value;
}

static inline void outsb(uint16_t port, const void *data, size_t count) {
    asm("rep outsb" ::"d"(port), "S"(data), "c"(count) : "memory");
}

static inline void outsw(uint16_t port, const void *data, size_t count) {
    asm("rep outsw" ::"d"(port), "S"(data), "c"(count) : "memory");
}

static inline void outsl(uint16_t port, const void *data, size_t count) {
    asm("rep outsl" ::"d"(port), "S"(data), "c"(count) : "memory");
}

static inline void insb(uint16_t port, void *data, size_t count) {
    asm("rep insb" ::"d"(port), "D"(data), "c"(count) : "memory");
}

static inline void insw(uint16_t port, void *data, size_t count) {
    asm("rep insw" ::"d"(port), "D"(data), "c"(count) : "memory");
}

static inline void insl(uint16_t port, void *data, size_t count) {
    asm("rep insl" ::"d"(port), "D"(data), "c"(count) : "memory");
}
