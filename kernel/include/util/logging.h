#pragma once

#include <stdarg.h>
#include <stddef.h>

void klog_write(const void *data, size_t count);

void vprintk(const char *format, va_list args);
void printk(const char *format, ...);

size_t vsnprintk(void *buffer, size_t size, const char *format, va_list args);
size_t snprintk(void *buffer, size_t size, const char *format, ...);
