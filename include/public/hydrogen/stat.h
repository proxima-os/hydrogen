#ifndef HYDROGEN_STAT_H
#define HYDROGEN_STAT_H

#ifdef __cplusplus
extern "C" {
#endif

#define S_IXOTH (1u << 0)
#define S_IWOTH (1u << 1)
#define S_IROTH (1u << 2)
#define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#define S_IXGRP (1u << 3)
#define S_IWGRP (1u << 4)
#define S_IRGRP (1u << 5)
#define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#define S_IXUSR (1u << 6)
#define S_IWUSR (1u << 7)
#define S_IRUSR (1u << 8)
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#define S_ISVTX (1u << 9)
#define S_ISGID (1u << 10)
#define S_ISUID (1u << 11)

#define S_IFMT (7u << 12)
#define S_IFDIR (1u << 12)
#define S_IFLNK (2u << 12)
#define S_IFREG (3u << 12)
#define S_IFCHR (4u << 12)
#define S_IFBLK (5u << 12)
#define S_IFIFO (6u << 12)
#define S_IFSOCK (7u << 12)

#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#ifdef __cplusplus
};
#endif

#endif // HYDROGEN_STAT_H
