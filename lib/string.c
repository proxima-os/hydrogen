#include <stddef.h>
#include <stdint.h>

char *strchr(const char *s, int c) {
    char find = c;

    for (;;) {
        char cur = *s;
        if (cur == find) return (char *)s;
        if (!cur) return NULL;
        s++;
    }
}

int strcmp(const char *s1, const char *s2) {
    for (;;) {
        unsigned char c1 = *s1++;
        unsigned char c2 = *s2++;

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) return 0;
    }
}

size_t strlen(const char *s) {
    size_t i = 0;
    while (*s++) i++;
    return i;
}

size_t strnlen(const char *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i] != 0) i++;
    return i;
}
