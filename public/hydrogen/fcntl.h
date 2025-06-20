#ifndef _HYDROGEN_FCNTL_H
#define _HYDROGEN_FCNTL_H

#ifdef __cplusplus
extern "C" {
#endif

#define __O_RDONLY (1 << 0)
#define __O_WRONLY (1 << 1)
#define __O_CLOFORK (1 << 2)
#define __O_CREAT (1 << 3)
#define __O_DIRECTORY (1 << 4)
#define __O_EXCL (1 << 5)
#define __O_NOFOLLOW (1 << 6)
#define __O_TRUNC (1 << 7)
#define __O_APPEND (1 << 8)
#define __O_CLOEXEC (1 << 9)
#define __O_NONBLOCK (1 << 10)
#define __O_TMPFILE (1 << 11)
#define __O_NOCTTY (1 << 12)

#define __AT_SYMLINK_FOLLOW (1 << 0)
#define __AT_REMOVEDIR (1 << 1)
#define __AT_EACCESS (1 << 2)
#define __AT_SYMLINK_NOFOLLOW (1 << 3)

#ifdef __cplusplus
};
#endif

#endif /* _HYDROGEN_FCNTL_H */
