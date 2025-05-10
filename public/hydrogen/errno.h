/** \file
 * Error codes.
 */

#ifndef __HYDROGEN_ERRNO_H
#define __HYDROGEN_ERRNO_H

#define __E2BIG 1            /**< Argument list too long. */
#define __EACCES 2           /**< Permission denied. */
#define __EADDRINUSE 3       /**< Address in use. */
#define __EADDRNOTAVAIL 4    /**< Address not available. */
#define __EAFNOSUPPORT 5     /**< Address family not supported. */
#define __EAGAIN 6           /**< Resource unavailable, try again. */
#define __EALREADY 7         /**< Connection already in progress. */
#define __EBADF 8            /**< Invalid handle. */
#define __EBADMSG 9          /**< Bad message. */
#define __EBUSY 10           /**< Device or resource busy. */
#define __ECANCELED 11       /**< Operation canceled. */
#define __ECHILD 12          /**< No child processes. */
#define __ECONNABORTED 13    /**< Connection aborted. */
#define __ECONNREFUSED 14    /**< Connection refused. */
#define __ECONNRESET 15      /**< Connection reset. */
#define __EDEADLK 16         /**< Resource deadlock would occur. */
#define __EDESTADDRREQ 17    /**< Destination address required. */
#define __EDOM 18            /**< Mathematics argument out of domain of function. */
#define __EDQUOT 19          /**< Reserved. */
#define __EEXIST 20          /**< Already exists. */
#define __EFAULT 21          /**< Invalid pointer. */
#define __EFBIG 22           /**< File too large. */
#define __EHOSTUNREACH 23    /**< Host is unreachable. */
#define __EIDRM 24           /**< Identifier removed. */
#define __EILSEQ 25          /**< Illegal byte sequence. */
#define __EINPROGRESS 26     /**< Operation in progress. */
#define __EINTR 27           /**< Function was interrupted. */
#define __EINVAL 28          /**< Invalid argument. */
#define __EIO 29             /**< I/O error. */
#define __EISCONN 30         /**< Socket is connected. */
#define __EISDIR 31          /**< Is a directory. */
#define __ELOOP 32           /**< Too many levels of symbolic links. */
#define __EMFILE 33          /**< No free handles available. */
#define __EMLINK 34          /**< Too many hard links. */
#define __EMSGSIZE 35        /**< Message too large. */
#define __EMULTIHOP 36       /**< Reserved. */
#define __ENAMETOOLONG 37    /**< Filename too long. */
#define __ENETDOWN 38        /**< Network is down. */
#define __ENETRESET 39       /**< Connection aborted by network. */
#define __ENETUNREACH 40     /**< Network unreachable. */
#define __ENFILE 41          /**< Too many files open in system. */
#define __ENOBUFS 42         /**< No buffer space available. */
#define __ENODEV 43          /**< No such device. */
#define __ENOENT 44          /**< Not found. */
#define __ENOEXEC 45         /**< Executable file format error. */
#define __ENOLCK 46          /**< No locks available. */
#define __ENOLINK 47         /**< Reserved. */
#define __ENOMEM 48          /**< Not enough space. */
#define __ENOMSG 49          /**< No message of the desired type. */
#define __ENOPROTOOPT 50     /**< Protocol not available. */
#define __ENOSPC 51          /**< No space left on device. */
#define __ENOSYS 52          /**< Functionality not supported. */
#define __ENOTCONN 53        /**< The socket is not connected. */
#define __ENOTDIR 54         /**< Not a directory. */
#define __ENOTEMPTY 55       /**< Directory not empty. */
#define __ENOTRECOVERABLE 56 /**< State not recoverable. */
#define __ENOTSOCK 57        /**< Not a socket. */
#define __ENOTSUP 58         /**< Not supported. */
#define __ENOTTY 59          /**< Inappropriate I/O control operation. */
#define __ENXIO 60           /**< No such device or address. */
#define __EOVERFLOW 61       /**< Value too large to be stored in data type. */
#define __EOWNERDEAD 62      /**< Previous owner died. */
#define __EPERM 63           /**< Operation not permitted. */
#define __EPIPE 64           /**< Broken pipe. */
#define __EPROTO 65          /**< Protocol error. */
#define __EPROTONOSUPPORT 66 /**< Protocol not supported. */
#define __EPROTOTYPE 67      /**< Protocol wrong type for socket. */
#define __ERANGE 68          /**< Result too large. */
#define __EROFS 69           /**< Read-only file system. */
#define __ESOCKTNOSUPPORT 70 /**< Socket type not supported. */
#define __ESPIPE 71          /**< Invalid seek. */
#define __ESRCH 72           /**< No such process. */
#define __ESTALE 73          /**< Reserved. */
#define __ETIMEDOUT 74       /**< Connection timed out. */
#define __ETXTBSY 75         /**< Text file busy. */
#define __EXDEV 76           /**< Improper hard link. */

#endif /* __HYDROGEN_ERRNO_H */
