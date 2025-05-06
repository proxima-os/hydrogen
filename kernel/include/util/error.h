#pragma once

#include "errno.h"

static inline const char *error_to_string(int error) {
    switch (error) {
    case E2BIG: return "E2BIG";
    case EACCES: return "EACCES";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EAGAIN: return "EAGAIN";
    case EALREADY: return "EALREADY";
    case EBADF: return "EBADF";
    case EBADMSG: return "EBADMSG";
    case EBUSY: return "EBUSY";
    case ECANCELED: return "ECANCELED";
    case ECHILD: return "ECHILD";
    case ECONNABORTED: return "ECONNABORTED";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ECONNRESET: return "ECONNRESET";
    case EDEADLK: return "EDEADLK";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    case EDOM: return "EDOM";
    case EDQUOT: return "EDQUOT";
    case EEXIST: return "EEXIST";
    case EFAULT: return "EFAULT";
    case EFBIG: return "EFBIG";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case EIDRM: return "EIDRM";
    case EILSEQ: return "EILSEQ";
    case EINPROGRESS: return "EINPROGRESS";
    case EINTR: return "EINTR";
    case EINVAL: return "EINVAL";
    case EIO: return "EIO";
    case EISCONN: return "EISCONN";
    case EISDIR: return "EISDIR";
    case ELOOP: return "ELOOP";
    case EMFILE: return "EMFILE";
    case EMLINK: return "EMLINK";
    case EMSGSIZE: return "EMSGSIZE";
    case EMULTIHOP: return "EMULTIHOP";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENETDOWN: return "ENETDOWN";
    case ENETRESET: return "ENETRESET";
    case ENETUNREACH: return "ENETUNREACH";
    case ENFILE: return "ENFILE";
    case ENOBUFS: return "ENOBUFS";
    case ENODEV: return "ENODEV";
    case ENOENT: return "ENOENT";
    case ENOEXEC: return "ENOEXEC";
    case ENOLCK: return "ENOLCK";
    case ENOLINK: return "ENOLINK";
    case ENOMEM: return "ENOMEM";
    case ENOMSG: return "ENOMSG";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case ENOSPC: return "ENOSPC";
    case ENOSYS: return "ENOSYS";
    case ENOTCONN: return "ENOTCONN";
    case ENOTDIR: return "ENOTDIR";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
    case ENOTSOCK: return "ENOTSOCK";
    case ENOTSUP: return "ENOTSUP";
    case ENOTTY: return "ENOTTY";
    case ENXIO: return "ENXIO";
    case EOVERFLOW: return "EOVERFLOW";
    case EOWNERDEAD: return "EOWNERDEAD";
    case EPERM: return "EPERM";
    case EPIPE: return "EPIPE";
    case EPROTO: return "EPROTO";
    case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
    case EPROTOTYPE: return "EPROTOTYPE";
    case ERANGE: return "ERANGE";
    case EROFS: return "EROFS";
    case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
    case ESPIPE: return "ESPIPE";
    case ESRCH: return "ESRCH";
    case ESTALE: return "ESTALE";
    case ETIMEDOUT: return "ETIMEDOUT";
    case ETXTBSY: return "ETXTBSY";
    case EXDEV: return "EXDEV";
    default: return "Unknown error";
    }
}
