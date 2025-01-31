#include <stddef.h>

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *b1 = s1;
    const unsigned char *b2 = s2;

    while (n--) {
        unsigned char c1 = *b1++;
        unsigned char c2 = *b2++;

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }

    return 0;
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

    while (n--) {
        *d++ = *s++;
    }

    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

    if (dest < src) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;

        while (n--) {
            *--d = *--s;
        }
    }

    return dest;
}

void *memset(void *dest, int value, size_t n) {
    unsigned char *d = dest;

    while (n--) {
        *d++ = value;
    }

    return dest;
}

size_t strlen(const char *s) {
    size_t i = 0;
    while (*s++) i++;
    return i;
}
